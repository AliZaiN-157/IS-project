const API_URL = "http://127.0.0.1:8000/predict";

document.addEventListener("DOMContentLoaded", () => {
  const statusIcon = document.getElementById("status-icon");
  const statusText = document.getElementById("status-text");

  // Get the active tab's URL
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const url = tabs[0].url;

    fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url }),
    })
      .then((response) => response.json())
      .then((data) => {
        if (data.prediction === "malware" || data.prediction === "phishing" 
          || data.prediction === "defacement"|| data.prediction === "spam"){

          statusIcon.src = "icons/not-safe.png";
          statusText.textContent = "Not Secure";
          statusText.className = "not-safe";

        } else {

          statusIcon.src = "icons/safe.png";
          statusText.textContent = "Secure";
          statusText.className = "safe";
        }
      })
      .catch((error) => {

        console.error("Error checking URL:", error);
        statusText.textContent = "Error checking URL.";

      });
  });
});
