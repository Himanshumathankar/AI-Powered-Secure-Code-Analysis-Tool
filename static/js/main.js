/* main.js – UI helpers for AI-Powered Secure Code Analysis Tool */

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('analyzeForm');
  const submitBtn = document.getElementById('submitBtn');
  const codeArea = document.getElementById('code');
  const fileInput = document.getElementById('file');

  if (!form) return;

  // When a file is selected, clear the textarea (and vice versa)
  if (fileInput) {
    fileInput.addEventListener('change', () => {
      if (fileInput.files.length > 0 && codeArea) {
        codeArea.value = '';
      }
    });
  }

  if (codeArea && fileInput) {
    codeArea.addEventListener('input', () => {
      if (codeArea.value.trim().length > 0) {
        fileInput.value = '';
      }
    });
  }

  // Show loading state on submit
  form.addEventListener('submit', (e) => {
    const hasCode = codeArea && codeArea.value.trim().length > 0;
    const hasFile = fileInput && fileInput.files.length > 0;

    if (!hasCode && !hasFile) {
      e.preventDefault();
      alert('Please paste code or upload a file before analysing.');
      return;
    }

    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = '⏳ Analysing…';
    }
  });
});
