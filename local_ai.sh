# smaller context size fails in almost every tool

llama-server -hf unsloth/Qwen3.5-35B-A3B-GGUF:IQ3_S \
    --ctx-size 65768 \
    --temp 0.6 \
    --top-p 0.95 \
    --top-k 20 \
    --min-p 0.00 \
    --alias "unsloth/Qwen3.5-35B-A3B-GGUF" \
    --port 8001 \
    --chat-template-kwargs '{"enable_thinking":true}'