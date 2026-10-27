#!/bin/bash

. venv/bin/activate

# ./hornet.sh [script.py] — an optional Python file drives the game with
# synthetic keys and clicks once it's up (macrt.ui.automation.Controller).


python -m macrt \
    --model ii \
    --host screen --menubar global \
    /Users/geordiemillar/ghidra-fa18/qemu/MacStartup512MB_4.img \
    --app "MacStartup512:F/A-18 Hornet Classic:F/A-18 Hornet Classic" \
    --system /Users/geordiemillar/ghidra-fa18/qemu/MacStartup512MB_4.img \
    --trace-traps \
    --suppress-traps TickCount,GetKeys,GetMouse,Button,SwapMMUMode,GetNextEvent \
    --ghidra-project /Users/geordiemillar/ghidra-fa18/fa18_classic.gpr \
    --symbols /Users/geordiemillar/ghidra-fa18/fa18-hornet-app/1.1.2_classic/symbols_classic.json \
    --size 1024x768 \
    --inject hornet_patch.py \
    --trace-functions \
    --log hornet.log
