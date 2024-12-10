from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
from model import predict_url 

app = FastAPI()

class URLRequest(BaseModel):
    url: str

@app.post("/predict/")
async def predict(request: URLRequest):
    try:
        prediction = predict_url(request.url)
        return {"url": request.url, "prediction": prediction}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
