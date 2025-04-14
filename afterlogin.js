// Function to escape HTML to prevent XSS
function escapeHTML(str) {
  const div = document.createElement('div');
  div.appendChild(document.createTextNode(str));
  return div.innerHTML;
}

// Get CSRF token and set it in forms
async function initializeCSRF() {
  try {
    const response = await fetch('/csrf-token', { credentials: 'same-origin' });
    if (!response.ok) throw new Error('Failed to fetch CSRF token');
    const { csrfToken } = await response.json();
    
    // Set CSRF token in all forms
    document.getElementById('csrfToken').value = csrfToken;
    document.getElementById('searchCsrfToken').value = csrfToken;
    
    return csrfToken;
  } catch (error) {
    console.error('Error initializing CSRF:', error);
    throw error;
  }
}

// Function to load and display comments from the server
async function loadComments() {
  try {
    const csrfToken = await initializeCSRF();
    const res = await fetch('/comments', { 
      credentials: 'same-origin',
      headers: {
        'X-CSRF-Token': csrfToken
      }
    });
    if (!res.ok) throw new Error('Failed to fetch comments');
    const comments = await res.json();
    const list = document.getElementById('commentList');
    list.innerHTML = '';
    comments.forEach(c => {
      const item = document.createElement('li');
      item.innerHTML = `
        <strong>${escapeHTML(c.name)}:</strong> <span>${escapeHTML(c.comment)}</span>
        <button class="delete-btn" data-id="${c.id}">Delete</button>
        <button class="edit-btn" data-id="${c.id}" data-comment="${escapeHTML(c.comment)}">Edit</button>
      `;
      list.appendChild(item);
    });

    // Event listeners for buttons
    document.querySelectorAll('.delete-btn').forEach(button => {
      button.addEventListener('click', () => deleteComment(button.dataset.id));
    });

    document.querySelectorAll('.edit-btn').forEach(button => {
      button.addEventListener('click', () => editComment(button.dataset.id, button.dataset.comment));
    });

    console.log('Comments loaded successfully');
  } catch (error) {
    console.error('Error loading comments:', error);
  }
}

// Event listener for posting a new comment
document.getElementById('commentForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const formData = new FormData(e.target);
  try {
    const csrfToken = await initializeCSRF();
    const res = await fetch('/create', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'X-CSRF-Token': csrfToken
      },
      body: new URLSearchParams(formData)
    });
    if (!res.ok) throw new Error('Failed to create comment');
    e.target.reset();
    loadComments();
    console.log('Comment submitted successfully');
  } catch (error) {
    console.error('Error submitting comment:', error);
  }
});

// Delete comment
async function deleteComment(id) {
  try {
    const csrfToken = await initializeCSRF();
    const res = await fetch(`/delete/${id}`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'X-CSRF-Token': csrfToken,
        'Content-Type': 'application/json'
      }
    });
    if (!res.ok) throw new Error('Failed to delete comment');
    loadComments();
    console.log(`Comment with ID ${id} deleted successfully`);
  } catch (error) {
    console.error(`Error deleting comment with ID ${id}:`, error);
  }
}

// Edit comment
async function editComment(id, oldComment) {
  const newComment = prompt('Edit your comment:', oldComment);
  if (newComment !== null && newComment.trim() !== '') {
    try {
      const csrfToken = await initializeCSRF();
      const res = await fetch(`/update/${id}`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'X-CSRF-Token': csrfToken,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ comment: newComment })
      });
      if (!res.ok) throw new Error('Failed to update comment');
      loadComments();
      console.log(`Comment with ID ${id} updated successfully`);
    } catch (error) {
      console.error(`Error updating comment with ID ${id}:`, error);
    }
  }
}

// Load comments on page load
loadComments();