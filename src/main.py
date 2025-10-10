from fastapi import FastAPI

app = FastAPI(title="Password Manager API")


@app.get("/")
def read_root():
    return {"status": "API is running"}
