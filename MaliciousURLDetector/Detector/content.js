const extractLinks = () => {
    const links = Array.from(document.querySelectorAll("a")).map(link => link.href);
    return [...new Set(links)];
  };
  
  const analyzeLinks = async (links) => {
    const results = { benign: 0, phishing: 0, defacement: 0, malicious: 0, spam:0 };
  
    // Replace this with your model's API endpoint or function call
    for (const link of links) {
      const prediction = await predictURL(link); // Example API call
      results[prediction]++;
    }
  
    return results;
  };
  
  // Fake prediction function for demonstration (replace with your actual model call)
  const predictURL = async (url) => {
    // Simulate prediction result (benign/phishing/malicious/defacement)
    const categories = ['defacement', 'benign', 'phishing', 'malware', 'spam']
    return categories[Math.floor(Math.random() * categories.length)];
  };
  
  const highlightLinks = (links, categories) => {
    links.forEach((link, index) => {
      if (categories[index] === "malicious") {
        link.style.border = "2px solid red";
      } else if (categories[index] === "phishing") {
        link.style.border = "2px solid orange";
      } else if (categories[index] === "defacement") {
        link.style.border = "2px solid yellow";
      }
    });
  };
  
  (async () => {
    const links = extractLinks();
    const results = await analyzeLinks(links);
  
    const safetyPercentage =
      (results.benign / links.length) * 100;
  
    chrome.runtime.sendMessage({
      type: "updateIcon",
      icon: safetyPercentage > 80 ? "secure" : safetyPercentage > 50 ? "caution" : "danger"
    });
  
    // Send results to popup
    chrome.storage.local.set({ stats: results, totalLinks: links.length });
  
    // Highlight links
    highlightLinks(document.querySelectorAll("a"), results);
  })();
  