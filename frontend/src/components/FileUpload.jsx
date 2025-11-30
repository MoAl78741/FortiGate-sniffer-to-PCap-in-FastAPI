import { useCallback, useState } from 'react';
import { useDropzone } from 'react-dropzone';
import { Upload, FileText, X, Eye, ArrowUpCircle } from 'lucide-react';

export function FileUpload({ onUpload }) {
  const [files, setFiles] = useState([]);
  const [previewing, setPreviewing] = useState(null);
  const [previewContent, setPreviewContent] = useState('');
  const [uploading, setUploading] = useState(false);

  const onDrop = useCallback((acceptedFiles) => {
    setFiles((prev) => [...prev, ...acceptedFiles]);
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { 'text/plain': ['.txt', '.log'] },
    maxSize: 20 * 1024 * 1024,
  });

  const removeFile = (index) => {
    setFiles((prev) => prev.filter((_, i) => i !== index));
  };

  const previewFile = async (file) => {
    const text = await file.text();
    setPreviewContent(text.slice(0, 15000) + (text.length > 15000 ? '\n\n... (truncated)' : ''));
    setPreviewing(file.name);
  };

  const handleUpload = async () => {
    if (files.length === 0) return;
    setUploading(true);
    try {
      await onUpload(files);
      setFiles([]);
    } finally {
      setUploading(false);
    }
  };

  const formatSize = (bytes) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  return (
    <div style={styles.container}>
      <div
        {...getRootProps()}
        style={{
          ...styles.dropzone,
          ...(isDragActive ? styles.dropzoneActive : {}),
        }}
      >
        <input {...getInputProps()} />
        <div style={styles.dropzoneIcon}>
          <Upload size={24} />
        </div>
        <p style={styles.dropzoneTitle}>
          {isDragActive ? 'Drop files here' : 'Drop sniffer captures here'}
        </p>
        <p style={styles.dropzoneSubtitle}>
          or click to browse. Supports .txt and .log (max 20MB)
        </p>
      </div>

      {files.length > 0 && (
        <div style={styles.fileSection}>
          <div style={styles.fileHeader}>
            <span style={styles.fileCount}>{files.length} file{files.length > 1 ? 's' : ''} selected</span>
            <button style={styles.clearBtn} onClick={() => setFiles([])}>
              Clear all
            </button>
          </div>

          <div style={styles.fileList}>
            {files.map((file, index) => (
              <div key={index} style={styles.fileItem}>
                <div style={styles.fileIcon}>
                  <FileText size={18} />
                </div>
                <div style={styles.fileInfo}>
                  <span style={styles.fileName}>{file.name}</span>
                  <span style={styles.fileSize}>{formatSize(file.size)}</span>
                </div>
                <div style={styles.fileActions}>
                  <button
                    style={styles.actionBtn}
                    onClick={() => previewFile(file)}
                    title="Preview"
                  >
                    <Eye size={16} />
                  </button>
                  <button
                    style={styles.actionBtn}
                    onClick={() => removeFile(index)}
                    title="Remove"
                  >
                    <X size={16} />
                  </button>
                </div>
              </div>
            ))}
          </div>

          <button
            style={{
              ...styles.uploadBtn,
              opacity: uploading ? 0.6 : 1,
              cursor: uploading ? 'not-allowed' : 'pointer',
            }}
            onClick={handleUpload}
            disabled={uploading}
          >
            <ArrowUpCircle size={18} />
            {uploading ? 'Uploading...' : 'Upload files'}
          </button>
        </div>
      )}

      {previewing && (
        <div style={styles.previewOverlay} onClick={() => setPreviewing(null)}>
          <div style={styles.previewModal} onClick={(e) => e.stopPropagation()}>
            <div style={styles.previewHeader}>
              <span style={styles.previewTitle}>{previewing}</span>
              <button style={styles.previewClose} onClick={() => setPreviewing(null)}>
                <X size={18} />
              </button>
            </div>
            <div style={styles.previewBody}>
              <pre style={styles.previewCode}>{previewContent}</pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

const styles = {
  container: {
    marginBottom: '32px',
  },
  dropzone: {
    border: '2px dashed var(--border)',
    borderRadius: 'var(--radius-lg)',
    padding: '48px 24px',
    textAlign: 'center',
    cursor: 'pointer',
    transition: 'all 0.2s',
    background: 'var(--bg-secondary)',
  },
  dropzoneActive: {
    borderColor: 'var(--accent)',
    background: 'var(--accent-muted)',
  },
  dropzoneIcon: {
    width: '48px',
    height: '48px',
    borderRadius: 'var(--radius-md)',
    background: 'var(--bg-tertiary)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    margin: '0 auto 16px',
    color: 'var(--text-muted)',
  },
  dropzoneTitle: {
    fontSize: '15px',
    fontWeight: '500',
    marginBottom: '6px',
    color: 'var(--text-primary)',
  },
  dropzoneSubtitle: {
    fontSize: '13px',
    color: 'var(--text-muted)',
  },
  fileSection: {
    marginTop: '16px',
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-lg)',
    overflow: 'hidden',
  },
  fileHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '12px 16px',
    borderBottom: '1px solid var(--border)',
  },
  fileCount: {
    fontSize: '13px',
    fontWeight: '500',
    color: 'var(--text-secondary)',
  },
  clearBtn: {
    fontSize: '13px',
    color: 'var(--text-muted)',
    background: 'none',
    border: 'none',
    cursor: 'pointer',
    padding: 0,
  },
  fileList: {
    maxHeight: '240px',
    overflow: 'auto',
  },
  fileItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    padding: '12px 16px',
    borderBottom: '1px solid var(--border)',
  },
  fileIcon: {
    width: '36px',
    height: '36px',
    borderRadius: 'var(--radius-sm)',
    background: 'var(--bg-tertiary)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    color: 'var(--accent)',
    flexShrink: 0,
  },
  fileInfo: {
    flex: 1,
    minWidth: 0,
  },
  fileName: {
    display: 'block',
    fontSize: '14px',
    fontWeight: '500',
    color: 'var(--text-primary)',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  fileSize: {
    fontSize: '12px',
    color: 'var(--text-muted)',
  },
  fileActions: {
    display: 'flex',
    gap: '4px',
  },
  actionBtn: {
    width: '32px',
    height: '32px',
    borderRadius: 'var(--radius-sm)',
    border: 'none',
    background: 'transparent',
    color: 'var(--text-muted)',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    transition: 'background 0.15s, color 0.15s',
  },
  uploadBtn: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '8px',
    width: '100%',
    padding: '14px',
    fontSize: '14px',
    fontWeight: '500',
    border: 'none',
    background: 'var(--accent)',
    color: 'white',
    cursor: 'pointer',
  },
  previewOverlay: {
    position: 'fixed',
    inset: 0,
    background: 'rgba(0, 0, 0, 0.8)',
    backdropFilter: 'blur(4px)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '24px',
    zIndex: 100,
  },
  previewModal: {
    width: '100%',
    maxWidth: '800px',
    maxHeight: '80vh',
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-lg)',
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
  },
  previewHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '16px 20px',
    borderBottom: '1px solid var(--border)',
  },
  previewTitle: {
    fontSize: '14px',
    fontWeight: '500',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  previewClose: {
    width: '32px',
    height: '32px',
    borderRadius: 'var(--radius-sm)',
    border: 'none',
    background: 'var(--bg-tertiary)',
    color: 'var(--text-secondary)',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  },
  previewBody: {
    flex: 1,
    overflow: 'auto',
    padding: '20px',
  },
  previewCode: {
    fontFamily: 'ui-monospace, "SF Mono", Menlo, Monaco, monospace',
    fontSize: '12px',
    lineHeight: '1.6',
    color: 'var(--text-secondary)',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-all',
    margin: 0,
  },
};
