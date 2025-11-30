

//rename task
let renameTaskId;

function renameFile() {
  let newname = document.getElementById("txt-content").value;
  if (!newname.trim()) {
    return;
  }
  fetch(`/rename/${renameTaskId}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    credentials: "same-origin",
    body: JSON.stringify({ new_name: newname }),
  }).then((res) => {
    if (res.ok) {
      window.location.href = "/";
    } else {
      alert("Failed to rename file");
    }
  });
}

function renameFileTaskId(id) {
  renameTaskId = id;
  // Clear the input field when opening modal
  document.getElementById("txt-content").value = "";
}


//prevent enter key in textbox
$("textarea").keydown(function(e){
  // Enter pressed
  if (e.keyCode == 13)
  {
      //method to prevent from default behaviour
      e.preventDefault();
  }
});

//dropzone
$(document).ready(function() {
  $("#input-b5").fileinput({showCaption: false, dropZoneEnabled: false});
});