chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "updateIcon") {
      chrome.action.setIcon({ path: `icons/${message.icon}.png` });
    }
  });
  