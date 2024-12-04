from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
from model import predict_url  # Import the prediction function from model.py

app = FastAPI()

# Define the request body structure
class URLRequest(BaseModel):
    url: str

@app.post("/predict/")
async def predict(request: URLRequest):
    try:
        prediction = predict_url(request.url)  # Pass URL to model for prediction
        return {"url": request.url, "prediction": prediction}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
