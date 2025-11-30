import os
from typing import List
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from fastapi.responses import FileResponse, Response
from sqlmodel import Session, select
from ..core.database import get_session
from ..models.user import User
from ..models.conversion import Conversion
from ..schemas.conversion import ConversionRead, ConversionRename
from ..services.converter import Convert2Pcap
from ..core.security import settings
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    statement = select(User).where(User.email == email)
    user = session.exec(statement).first()
    if user is None:
        raise credentials_exception
    return user

@router.post(
    "/upload",
    response_model=List[ConversionRead],
    summary="Upload sniffer files",
    description="Upload one or more FortiGate sniffer output files for conversion. Files are stored and can be converted to PCAP format later.",
    responses={
        200: {"description": "Files uploaded successfully"},
        401: {"description": "Not authenticated"},
    },
)
async def upload_files(
    files: List[UploadFile] = File(..., description="FortiGate sniffer output files to upload"),
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """
    Upload FortiGate sniffer files for conversion.

    Accepts multiple files in a single request. Filenames are sanitized to
    contain only alphanumeric characters, dots, underscores, and hyphens.
    """
    results = []
    for file in files:
        content = await file.read()
        # Sanitize filename
        filename = "".join(x for x in file.filename if x.isalnum() or x in "._-")

        conversion = Conversion(content=filename, data=content, user_id=current_user.id)
        session.add(conversion)
        session.commit()
        session.refresh(conversion)

        # Manually map to schema to handle computed fields
        results.append(ConversionRead(
            content=conversion.content,
            id=conversion.id,
            date_created=conversion.date_created,
            user_id=conversion.user_id,
            has_converted_data=conversion.data_converted is not None
        ))
    return results

@router.get(
    "/conversions",
    response_model=List[ConversionRead],
    summary="List all conversions",
    description="Get a list of all conversion tasks for the authenticated user.",
    responses={
        200: {"description": "List of conversion tasks"},
        401: {"description": "Not authenticated"},
    },
)
async def list_conversions(current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    """
    List all conversion tasks for the current user.

    Returns conversion metadata including whether each file has been converted.
    """
    statement = select(Conversion).where(Conversion.user_id == current_user.id)
    conversions = session.exec(statement).all()
    return [
        ConversionRead(
            content=c.content,
            id=c.id,
            date_created=c.date_created,
            user_id=c.user_id,
            has_converted_data=c.data_converted is not None
        ) for c in conversions
    ]

@router.post(
    "/convert/{id}",
    summary="Convert sniffer file to PCAP",
    description="Convert a previously uploaded FortiGate sniffer file to PCAPNG format. The converted file can then be downloaded.",
    responses={
        200: {"description": "Conversion successful, returns packet count"},
        401: {"description": "Not authenticated"},
        404: {"description": "Conversion task not found"},
        500: {"description": "Conversion failed"},
    },
)
async def convert_file(
    id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """
    Convert a sniffer file to PCAPNG format.

    - **id**: The conversion task ID returned from upload
    """
    conversion = session.get(Conversion, id)
    if not conversion or conversion.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Conversion task not found")

    try:
        pcap_path, packets = Convert2Pcap.run_conversion(
            tid=conversion.id,
            cid=current_user.id,
            tuid=conversion.user_id,
            fname=conversion.content,
            file_to_convert=conversion.data
        )

        with open(pcap_path, "rb") as f:
            conversion.data_converted = f.read()

        session.add(conversion)
        session.commit()

        # Cleanup
        os.remove(pcap_path)

        return {"message": f"Converted {packets} packets to PCAP successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get(
    "/conversions/{id}/download/original",
    summary="Download original sniffer file",
    description="Download the originally uploaded FortiGate sniffer file.",
    responses={
        200: {"description": "Original file download", "content": {"application/octet-stream": {}}},
        401: {"description": "Not authenticated"},
        404: {"description": "Conversion task not found"},
    },
)
async def download_original(
    id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """
    Download the original uploaded sniffer file.

    - **id**: The conversion task ID
    """
    conversion = session.get(Conversion, id)
    if not conversion or conversion.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Conversion task not found")

    return Response(
        content=conversion.data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={conversion.content}"}
    )

@router.get(
    "/conversions/{id}/download/pcap",
    summary="Download converted PCAP file",
    description="Download the converted PCAPNG file. The file must be converted first using the /convert endpoint.",
    responses={
        200: {"description": "PCAPNG file download", "content": {"application/x-pcapng": {}}},
        400: {"description": "File not converted yet"},
        401: {"description": "Not authenticated"},
        404: {"description": "Conversion task not found"},
    },
)
async def download_pcap(
    id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """
    Download the converted PCAPNG file.

    - **id**: The conversion task ID

    The file must be converted first using POST /convert/{id}.
    """
    conversion = session.get(Conversion, id)
    if not conversion or conversion.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Conversion task not found")

    if not conversion.data_converted:
        raise HTTPException(status_code=400, detail="File not converted yet")

    return Response(
        content=conversion.data_converted,
        media_type="application/x-pcapng",
        headers={"Content-Disposition": f"attachment; filename={conversion.content}.pcapng"}
    )

@router.delete(
    "/conversions/{id}",
    summary="Delete conversion task",
    description="Delete a conversion task and its associated files (both original and converted).",
    responses={
        200: {"description": "Deletion successful"},
        401: {"description": "Not authenticated"},
        404: {"description": "Conversion task not found"},
    },
)
async def delete_conversion(
    id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """
    Delete a conversion task.

    - **id**: The conversion task ID

    This permanently removes both the original and converted files.
    """
    conversion = session.get(Conversion, id)
    if not conversion or conversion.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Conversion task not found")

    session.delete(conversion)
    session.commit()
    return {"message": "Deleted successfully"}

@router.put(
    "/conversions/{id}",
    summary="Rename conversion task",
    description="Rename a conversion task. The new name is sanitized to contain only safe characters.",
    responses={
        200: {"description": "Rename successful"},
        401: {"description": "Not authenticated"},
        404: {"description": "Conversion task not found"},
    },
)
async def rename_conversion(
    id: int,
    rename: ConversionRename,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """
    Rename a conversion task.

    - **id**: The conversion task ID
    - **new_name**: The new filename (will be sanitized)
    """
    conversion = session.get(Conversion, id)
    if not conversion or conversion.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Conversion task not found")

    # Sanitize filename
    new_name = "".join(x for x in rename.new_name if x.isalnum() or x in "._-")
    conversion.content = new_name
    session.add(conversion)
    session.commit()
    return {"message": "Renamed successfully"}
