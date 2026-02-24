from fastapi import FastAPI

app = FastAPI()


@app.get("/")
def root():
    return {"status": "ok", "version": 1, "app": "testapp2"}
