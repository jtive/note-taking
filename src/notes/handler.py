"""Lambda entry point.

Mangum adapts the ASGI application to API Gateway's event format, so the same
code runs unchanged under `uvicorn` locally and under Lambda in AWS. It was
chosen over the AWS Lambda Web Adapter, which also works without code changes
but starts a real uvicorn server inside the execution environment and so pays
more on every cold start.

`lifespan="off"` because the app registers no startup or shutdown hooks;
expensive setup is cached lazily per execution environment instead.
"""

from mangum import Mangum

from notes.main import app

lambda_handler = Mangum(app, lifespan="off")
