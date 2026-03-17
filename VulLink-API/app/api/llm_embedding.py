from datetime import datetime
from typing import Optional, Dict
from fastapi import APIRouter, HTTPException, Request
import numpy as np
from sklearn.decomposition import PCA, IncrementalPCA
import asyncio
from concurrent.futures import ThreadPoolExecutor
import os
from dotenv import load_dotenv
import platform
from pathlib import Path

router = APIRouter()

MODEL_OPTIONS = ["mpnet", "secbert", "fasttext"]

IS_LINUX = platform.system().lower() == "linux"
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "")
env_path = Path(__file__).resolve().parent.parent.parent / ".env.development"
load_dotenv(dotenv_path=env_path)
if IS_LINUX:
    load_dotenv()

if IS_LINUX:
    DATA_DIR = os.getenv("DATA_DIR_LINUX")
else:
    DATA_DIR = os.getenv("DATA_DIR_WINDOWS")

DIM128_EMBEDDING = "embeddings/128"
DIM32_EMBEDDING = "embeddings/32"
CVEIDS_LIST = "cveIDs.npy"

DIM128_EMBEDDING_DIR = os.path.join(DATA_DIR, DIM128_EMBEDDING)
DIM32_EMBEDDING_DIR = os.path.join(DATA_DIR, DIM32_EMBEDDING)
CVEIDS_LIST_PATH = os.path.join(DATA_DIR, CVEIDS_LIST)

assert os.path.exists(DIM128_EMBEDDING_DIR), f"{DIM128_EMBEDDING_DIR} does not exists"
assert os.path.exists(DIM32_EMBEDDING_DIR), f"{DIM32_EMBEDDING_DIR} does not exists"
assert os.path.exists(CVEIDS_LIST_PATH), f"{CVEIDS_LIST_PATH} does not exists"

dim32_data: Dict[str, np.ndarray] = {}
dim128_data: Dict[str, np.ndarray] = {}
cveids_list: np.ndarray = None

executor = ThreadPoolExecutor(max_workers=4)

for model in MODEL_OPTIONS:
    dim32_data[model] = None
    dim128_data[model] = None


def load_data_and_cveids():
    global dim32_data, dim128_data, cveids_list

    try:

        for model in MODEL_OPTIONS:

            path32 = os.path.join(
                DIM32_EMBEDDING_DIR,
                f"embeddings32_{model}.npy"
            )

            if os.path.exists(path32):
                dim32_data[model] = np.load(path32)
                print(f"{model} dim32 loaded {dim32_data[model].shape}")

            path128 = os.path.join(
                DIM128_EMBEDDING_DIR,
                f"embeddings128_{model}.npy"
            )

            if os.path.exists(path128):
                dim128_data[model] = np.load(path128)
                print(f"{model} dim128 loaded {dim128_data[model].shape}")

        cveids_list = np.load(CVEIDS_LIST_PATH, allow_pickle=True)

        print("Loaded CVE list:", cveids_list.shape)

    except Exception as e:
        print("Error loading embeddings:", e)


print("Loading embeddings...")
load_data_and_cveids()


def run_pca(data: np.ndarray, n_components: int, chunksize: int = 1000):

    if data.shape[0] > 10000:

        ipca = IncrementalPCA(n_components=n_components)

        for i in range(0, data.shape[0], chunksize):
            ipca.partial_fit(data[i:i + chunksize])

        transformed_chunks = []

        for i in range(0, data.shape[0], chunksize):
            chunk = ipca.transform(data[i:i + chunksize])
            transformed_chunks.append(chunk)

        transformed = np.concatenate(transformed_chunks)

        return transformed.tolist()

    else:

        pca = PCA(n_components=n_components)
        transformed = pca.fit_transform(data)

        return transformed.tolist()


@router.get("")
async def get_llm_embeddings(
    request: Request,
    model: Optional[str] = "mpnet",
    year: Optional[int] = 1999,
    dim_size: Optional[int] = 32
):

    if model not in MODEL_OPTIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Model must be one of {MODEL_OPTIONS}"
        )

    if dim_size <= 0 or dim_size > 128:
        raise HTTPException(
            status_code=400,
            detail="dim_size must be between 1 and 128"
        )

    if year < 1999 or year > datetime.now().year:
        raise HTTPException(
            status_code=400,
            detail=f"Year must be between 1999 and {datetime.now().year}"
        )

    origin = request.headers.get("origin", "")
    is_frontend = bool(FRONTEND_ORIGIN and origin == FRONTEND_ORIGIN)

    if dim32_data[model] is None:
        raise HTTPException(500, f"Dim32 dataset for {model} not loaded")

    if dim_size > 32 and dim128_data[model] is None:
        raise HTTPException(500, f"Dim128 dataset for {model} not loaded")

    try:

        if dim_size <= 32:
            base_embeddings = dim32_data[model]
        else:
            base_embeddings = dim128_data[model]

        combined = np.column_stack((cveids_list, base_embeddings))

        target_year = str(year)

        mask = np.array([
            cve_id[4:8] == target_year
            for cve_id in combined[:, 0]
        ])

        year_data = combined[mask]

        if year_data.size == 0:
            return {
                "embeddings": [],
                "cveIDs": [],
                "message": f"No embeddings found for year {target_year}",
                "count": 0
            }

        raw_embeddings = year_data[:, 1:].astype(float)
        original_dim = raw_embeddings.shape[1]

        if not is_frontend and dim_size < original_dim:

            loop = asyncio.get_running_loop()

            embeddings = await loop.run_in_executor(
                executor,
                run_pca,
                raw_embeddings,
                dim_size
            )

        else:

            embeddings = raw_embeddings.tolist()

        return {
            "embeddings": embeddings,
            "cveIDs": year_data[:, 0].tolist(),
            "count": len(embeddings)
        }

    except Exception as e:

        raise HTTPException(
            status_code=400,
            detail=f"Error processing request: {str(e)}"
        )