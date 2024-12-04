document.addEventListener("DOMContentLoaded", async () => {
    const data = await chrome.storage.local.get(["stats", "totalLinks"]);
    const { stats, totalLinks } = data;
  
    document.getElementById("totalLinks").textContent = totalLinks;
    document.getElementById("benign").textContent = stats.benign;
    document.getElementById("phishing").textContent = stats.phishing;
    document.getElementById("defacement").textContent = stats.defacement;
    document.getElementById("malicious").textContent = stats.malicious;
  
    const safetyPercentage = (stats.benign / totalLinks) * 100;
    const chart = document.getElementById("safetyPercentage");
  
    chart.style.background = `conic-gradient(
      green ${safetyPercentage}%,
      red ${safetyPercentage}% 100%
    )`;
  });
  