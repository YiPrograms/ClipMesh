document.querySelector('#pair').addEventListener('click', async () => {
  const button = document.querySelector('#pair');
  const result = document.querySelector('#result');
  button.disabled = true;
  try {
    const response = await fetch('/api/v1/pairing', {method: 'POST', headers: {'content-type':'application/json'}, body: '{}'});
    if (!response.ok) throw new Error('Could not create a pairing code');
    const data = await response.json();
    result.textContent = data.code;
    result.hidden = false;
  } catch (error) {
    result.textContent = error.message;
    result.hidden = false;
  } finally { button.disabled = false; }
});

const platform = (navigator.userAgentData?.platform || navigator.platform || navigator.userAgent).toLowerCase();
const os = platform.includes('mac') ? 'macos' : platform.includes('win') ? 'windows' : platform.includes('linux') ? 'linux' : undefined;
if (os) document.querySelector(`.download-card[data-os="${os}"]`)?.classList.add('recommended');
