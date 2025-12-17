# ML Models for Layer 1 Lab

This folder contains ML models for optional advanced security controls. The lab works without these models using regex/keyword fallbacks.

## Recommended Installation Method (Git Clone)

The easiest way to install models, especially on corporate networks with SSL inspection:

```bash
cd models

# 1. Sentence Transformers (for embedding similarity)
git clone https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2

# 2. BERT (for Detoxify content safety)
git clone https://huggingface.co/google-bert/bert-base-uncased

# 3. spaCy (for PII detection) - Optional
git clone https://huggingface.co/spacy/en_core_web_lg
```

**Important**: After cloning, run the cleanup script to reduce file size by 55%:

```bash
# Remove unnecessary model formats (keeps only PyTorch)
cd all-MiniLM-L6-v2
Remove-Item -Force tf_model.h5, rust_model.ot, model.safetensors
Remove-Item -Recurse -Force onnx, openvino

cd ../bert-base-uncased  
Remove-Item -Force tf_model.h5, rust_model.ot, model.onnx, model.safetensors, flax_model.msgpack

cd ..
```

This reduces total size from ~5.8GB to ~2.6GB while keeping full functionality.

## Alternative: Manual Download

## Alternative: Manual Download

If git clone doesn't work, you can manually download files:

### 1. Sentence Transformers (Embedding Similarity Control)
**Model**: all-MiniLM-L6-v2

- **Download from**: https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/tree/main
- **Required files**: `pytorch_model.bin`, `config.json`, `tokenizer.json`, `vocab.txt`, plus the `1_Pooling/` folder
- **Optional**: Skip `tf_model.h5`, `rust_model.ot`, `model.safetensors`, `onnx/`, `openvino/` to save ~260MB
- **Place in**: `models/all-MiniLM-L6-v2/`

### 2. BERT Base (Required by Detoxify)
**Model**: bert-base-uncased

- **Download from**: https://huggingface.co/google-bert/bert-base-uncased/tree/main  
- **Required files**: `pytorch_model.bin` (420MB), `config.json`, `tokenizer.json`, `vocab.txt`
- **Optional**: Skip `tf_model.h5`, `rust_model.ot`, `model.onnx`, `flax_model.msgpack` to save ~2.9GB
- **Place in**: `models/bert-base-uncased/`

### 3. Detoxify Checkpoint
**File**: toxic_original-c1212f89.ckpt (418MB)

- **Direct link**: https://github.com/unitaryai/detoxify/releases/download/v0.1-alpha/toxic_original-c1212f89.ckpt
- **Place in**: `models/` folder (same directory as this README)

### 4. spaCy NER Model (PII Detection - Optional)
**Model**: en_core_web_lg

- **Git clone**: `git clone https://huggingface.co/spacy/en_core_web_lg`
- **Place in**: `models/en_core_web_lg/`
- **Then install**: Copy to spaCy's data directory or the lab will use Presidio's regex fallback

## How The Lab Finds Models

The lab automatically detects models in this order:

1. **Local `models/` directory** (this folder) - Checked first
2. **Python package cache** - `~/.cache/torch/`, `~/.cache/huggingface/`
3. **Fallback to download** - Attempts to download from Hugging Face (may fail with SSL errors)
4. **Regex fallback** - Uses simple regex patterns if models unavailable

## Verification

After installation, verify models work:

```python
# From the lab root directory
cd ..
python -c "
from sentence_transformers import SentenceTransformer
from detoxify import Detoxify
import spacy

# Test loading
model1 = SentenceTransformer('./models/all-MiniLM-L6-v2')
model2 = Detoxify('original')
nlp = spacy.load('en_core_web_lg')  # Optional

print('✅ All models working!')
"
```

## Note on Git Storage

**These model files are NOT stored in the git repository** due to their large size (600MB+ total). This folder provides instructions only. GitHub has a 100MB file size limit, and large binary files bloat repository history.

If you need to share models with your team, consider:
- Internal file server
- Cloud storage (S3, Azure Blob, GCS)
- Git LFS (Large File Storage) for enterprise repositories
- Shared network drive

## Why These Models Are Optional

The lab works without ML models using fallback implementations:
- **Embedding Similarity**: Disabled by default (this is an experimental control)
- **Content Safety**: Falls back to keyword-based detection
- **PII Detection**: Falls back to regex patterns

The core Layer 1 controls (Unicode normalization, HTML sanitization, regex injection detection, rate limiting) work out of the box with no ML dependencies.
