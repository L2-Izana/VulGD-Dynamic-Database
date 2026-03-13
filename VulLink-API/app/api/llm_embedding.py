from datetime import datetime
from typing import Optional, Dict, List
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
import numpy as np
from sklearn.decomposition import PCA, IncrementalPCA
import asyncio
from concurrent.futures import ThreadPoolExecutor
import os
from dotenv import load_dotenv
import pandas as pd
import platform
import sys

load_dotenv()

IS_LINUX = platform.system().lower() == 'linux'
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "")
if IS_LINUX:
    DATA_DIR=os.getenv("DATA_DIR_LINUX")
else:
    DATA_DIR=os.getenv("DATA_DIR_WINDOWS")

assert DATA_DIR and os.path.exists(DATA_DIR), f"Data directory {DATA_DIR} must exists"
DIM128_EMBEDDING="embeddings/128"
DIM32_EMBEDDING="embeddings/32"
CVEIDS_LIST="cveIDs.npy"
DIM128_EMBEDDING_DIR = os.path.join(DATA_DIR, DIM128_EMBEDDING)
DIM32_EMBEDDING_DIR = os.path.join(DATA_DIR, DIM32_EMBEDDING)
CVEIDS_LIST_PATH = os.path.join(DATA_DIR, CVEIDS_LIST)
assert os.path.exists(DIM128_EMBEDDING_DIR) and os.path.exists(DIM32_EMBEDDING_DIR) and os.path.exists(CVEIDS_LIST_PATH), f"The necessary embeddings and cveIds do not exists"

# Create a router instead of a FastAPI app
router = APIRouter()

# Determine the operating system

MODEL_OPTIONS = ["mpnet", "secbert", "fasttext"]

# Use environment variables for data paths based on OS

# Global variables to hold the datasets
dim32_data:Dict[str, np.ndarray] = {}
dim128_data:Dict[str, np.ndarray] = {}
cveids_list:np.ndarray = None
for model in MODEL_OPTIONS:
    dim32_data[model] = None
    dim128_data[model] = None

# Create a thread pool executor to offload CPU-intensive tasks.
executor = ThreadPoolExecutor(max_workers=4)

def load_data_and_cveids():
    """Load only the dim32 data at startup"""
    global dim32_data, dim128_data, cveids_list
    try:
        if os.path.exists(DIM32_EMBEDDING_DIR):
            # Check for model-specific subdirectories
            for model in MODEL_OPTIONS:
                file_name = f"embeddings32_{model}.npy"
                model_path = os.path.join(DIM32_EMBEDDING_DIR, file_name)
                if os.path.exists(model_path):
                    print(f"Found {model} embeddings directory at {model_path}")
                    dim32_data[model] = np.load(model_path)
                    print(f"Loaded {model} embeddings data with shape {dim32_data[model].shape}")
                else:
                    print(f"Warning: {model} embeddings directory not found at {model_path}")                        
        if os.path.exists(CVEIDS_LIST_PATH):
            cveids_list = np.load(CVEIDS_LIST_PATH, allow_pickle=True)
            print(f"Loaded cveids list with shape {cveids_list.shape}")
        else:
            print(f"Warning: cveIDs list not found at {CVEIDS_LIST_PATH}")
        if os.path.exists(DIM128_EMBEDDING_DIR):
            for model in MODEL_OPTIONS:
                file_name = f"embeddings128_{model}.npy"
                model_path = os.path.join(DIM128_EMBEDDING_DIR, file_name)
                if os.path.exists(model_path):
                    dim128_data[model] = np.load(model_path)
                    print(f"Loaded {model} embeddings data with shape {dim128_data[model].shape}")
                else:
                    print(f"Warning: {model} embeddings directory not found at {model_path}")
    except Exception as e:
        print(f"Error loading dim32 dataset: {e}")

# Only load dim32 data for all models and load list of cveIDs at startup
print("Loading dimension 32 and 128 data...")
load_data_and_cveids()

def run_pca(data: np.ndarray, n_components: int, chunksize: int = 1000):
    if data is None or data.size == 0:
        print("Dataset is empty")
        return None
        
    # Use IncrementalPCA if the dataset is large
    if data.shape[0] > 10000:
        ipca = IncrementalPCA(n_components=n_components)
        # Fit incrementally in batches
        for i in range(0, data.shape[0], chunksize):
            ipca.partial_fit(data[i:i+chunksize])
        transformed_chunks = []
        for i in range(0, data.shape[0], chunksize):
            end = min(i+chunksize, data.shape[0])
            transformed_chunk = ipca.transform(data[i:end])
            transformed_chunks.append(transformed_chunk)
        transformed_data = np.concatenate(transformed_chunks, axis=0)
        return {
            "transformed_data": transformed_data.tolist(),
            "explained_variance_ratio": ipca.explained_variance_ratio_.tolist()
        }
    else:
        pca = PCA(n_components=n_components)
        transformed_data = pca.fit_transform(data)
        return {
            "transformed_data": transformed_data.tolist(),
            "explained_variance_ratio": pca.explained_variance_ratio_.tolist()
        }

# @router.get("")
# async def get_llm_embeddings(model: Optional[str] = "mpnet", year: Optional[int] = 1999, dim_size: Optional[int] = 32):    
#     # Validate model
#     if model not in MODEL_OPTIONS:
#         raise HTTPException(
#             status_code=400,
#             detail=f"Model must be one of {MODEL_OPTIONS}"
#         )
    
#     # Check if data is loaded
#     if dim32_data[model] is None:
#         raise HTTPException(
#             status_code=500,
#             detail=f"Dim32 dataset for {model} not loaded"
#         )
    
#     if dim_size > 32 and dim128_data[model] is None:
#         raise HTTPException(
#             status_code=500,
#             detail=f"Dim128 dataset for {model} not loaded"
#         )
    
#     if year < 1999 or year > datetime.now().year:
#         raise HTTPException(
#             status_code=400,
#             detail=f"Year must be between 1999 and {datetime.now().year}"
#         )
    
#     try:
#         if dim_size <= 32:
#             # Use the pre-loaded dim32 data
#             chosen_dim32_data:  np.ndarray = dim32_data[model]
            
#             # Combine cveids_list and chosen_dim32_data
#             combined_data = np.column_stack((cveids_list, chosen_dim32_data))
#             # Filter by year
#             target_year = str(year)
#             year_mask = np.array([cve_id[4:8] == target_year for cve_id in combined_data[:, 0]])
#             year_data = combined_data[year_mask]

#             # If no data found, return empty list
#             if year_data.size == 0:
#                 return {
#                     "embeddings": [],
#                     "cveIDs": [],
#                     "message": f"No embeddings found for year {target_year}",
#                     "count": 0
#                 }
            
#             # Convert string representation of embeddings to list of floats
#             embeddings = year_data[:, 1:].tolist()
#             cve_ids = year_data[:, 0].tolist()

#             return {
#                 "embeddings": embeddings,
#                 "cveIDs": cve_ids,
#                 "count": len(embeddings),
#             }
#         elif dim_size > 128:
#             return {'message': 'Maximum dimension size is 128'}
#         else:                
#             # Use the pre-loaded dim32 data
#             chosen_dim128_data:  np.ndarray = dim128_data[model]
#             # Combine cveids_list and chosen_dim32_data
#             combined_data = np.column_stack((cveids_list, chosen_dim128_data))
#             # Filter by year
#             target_year = str(year)
#             year_mask = np.array([cve_id[4:8] == target_year for cve_id in combined_data[:, 0]])
#             year_data = combined_data[year_mask]
#             # If no data found, return empty list
#             if year_data.size == 0:
#                 return {
#                     "embeddings": [],
#                     "cveIDs": [],
#                     "message": f"No embeddings found for year {target_year}",
#                     "count": 0
#                 }
#             if dim_size == 128:
#                 # Convert string representation of embeddings to list of floats
#                 embeddings = year_data[:, 1:].tolist()
#                 cve_ids = year_data[:, 0].tolist()

#                 return {
#                     "embeddings": embeddings,
#                     "cveIDs": cve_ids,
#                     "count": len(embeddings),
#                 }
#             else:
#                 embeddings = year_data[:, 1:]
#                 loop = asyncio.get_running_loop()
#                 pca_result = await loop.run_in_executor(executor, run_pca, embeddings, dim_size)
                
#                 return {
#                     "embeddings": pca_result["transformed_data"],
#                     "cveIDs": year_data[:, 0].tolist(),
#                     "count": len(year_data),
#                 }
                
#     except Exception as e:
#         raise HTTPException(
#             status_code=400, 
#             detail=f"Error processing request: {str(e)}"
#         )

@router.get("")
async def get_llm_embeddings(
    request: Request,
    model: Optional[str] = "mpnet",
    year: Optional[int] = 1999,
    dim_size: Optional[int] = 32
):
    # 1) validate model…
    if model not in MODEL_OPTIONS:
        raise HTTPException(400, f"Model must be one of {MODEL_OPTIONS}")

    # 2) determine client type by Origin header
    origin = request.headers.get("origin", "")
    is_frontend = bool(FRONTEND_ORIGIN and origin == FRONTEND_ORIGIN)

    # 3) make sure data is loaded…
    if dim32_data[model] is None:
        raise HTTPException(500, f"Dim32 dataset for {model} not loaded")
    if dim_size > 32 and dim128_data[model] is None:
        raise HTTPException(500, f"Dim128 dataset for {model} not loaded")
    if year < 1999 or year > datetime.now().year:
        raise HTTPException(400, f"Year must be between 1999 and {datetime.now().year}")

    try:
        # grab the full‑dim arrays
        dim32_arr = dim32_data[model]
        dim128_arr = dim128_data[model]

        # 4) build a combined array depending on client type
        if is_frontend:
            # FRONTEND: send raw embeddings (browser will reduce)
            data_arr = dim32_arr if dim_size <= 32 else dim128_arr
            combined = np.column_stack((cveids_list, data_arr))

        else:
            # API: run PCA here if dim_size>32
            if dim_size <= 32:
                combined = np.column_stack((cveids_list, dim32_arr))
            elif dim_size > 128:
                return {"message": "Maximum dimension size is 128"}
            else:
                combined = np.column_stack((cveids_list, dim128_arr))

        # 5) filter by year
        target_year = str(year)
        year_mask = np.array([cve_id[4:8] == target_year for cve_id in combined[:, 0]])
        year_data = combined[year_mask]

        if year_data.size == 0:
            return {
                "embeddings": [],
                "cveIDs": [],
                "message": f"No embeddings found for year {target_year}",
                "count": 0
            }

        # 6) if API & requested dim_size>32, do the PCA shuffle
        if not is_frontend and 32 < dim_size <= 128:
            raw_emb = year_data[:, 1:].astype(float)
            loop = asyncio.get_running_loop()
            pca_res = await loop.run_in_executor(executor, run_pca, raw_emb, dim_size)
            embeddings = pca_res["transformed_data"]
        else:
            # either frontend (raw) or dim_size<=32 or dim_size==128
            embeddings = year_data[:, 1:].tolist()

        cve_ids = year_data[:, 0].tolist()
        return {
            "embeddings": embeddings,
            "cveIDs": cve_ids,
            "count": len(cve_ids),
        }

    except Exception as e:
        raise HTTPException(400, detail=f"Error processing request: {e}")