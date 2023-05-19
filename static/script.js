// Event handling for showing/hiding the sidebar
document.addEventListener('DOMContentLoaded', function () {
  var sidebarToggle = document.getElementById('sidebar-toggle');
  var sidebar = document.getElementById('sidebar');

  sidebarToggle.addEventListener('click', function () {
    sidebar.classList.toggle('active');
  });
});

// Event handling for showing/hiding the password field
document.addEventListener('DOMContentLoaded', function () {
  var passwordToggle = document.getElementById('password-toggle');
  var passwordField = document.getElementById('password');

  passwordToggle.addEventListener('change', function () {
    if (passwordToggle.checked) {
      passwordField.type = 'text';
    } else {
      passwordField.type = 'password';
    }
  });
});

// Toggle sidebar
function toggleSidebar() {
  const sidebar = document.querySelector('.sidebar');
  const content = document.querySelector('.content');
  const toggleButton = document.querySelector('.toggle-button');

  sidebar.classList.toggle('expanded');
  content.classList.toggle('expanded');

  if (sidebar.classList.contains('expanded')) {
    toggleButton.textContent = 'Close';
  } else {
    toggleButton.textContent = 'Menu';
  }
}
