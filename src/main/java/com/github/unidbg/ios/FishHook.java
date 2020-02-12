package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Symbol;
import com.github.unidbg.hook.BaseHook;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.fishhook.IFishHook;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;

public class FishHook extends BaseHook implements IFishHook {

    private static final Log log = LogFactory.getLog(FishHook.class);

    public static IFishHook getInstance(Emulator emulator) {
        IFishHook fishHook = emulator.get(FishHook.class.getName());
        if (fishHook == null) {
            try {
                fishHook = new FishHook(emulator);
                emulator.set(FishHook.class.getName(), fishHook);
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
        return fishHook;
    }

    private final Symbol rebind_symbols, rebind_symbols_image;

    private FishHook(Emulator emulator) throws IOException {
        super(emulator, "libfishhook");

        rebind_symbols = module.findSymbolByName("_rebind_symbols", false);
        rebind_symbols_image = module.findSymbolByName("_rebind_symbols_image", false);
        log.debug("rebind_symbols=" + rebind_symbols + ", rebind_symbols_image=" + rebind_symbols_image);

        if (rebind_symbols == null) {
            throw new IllegalStateException("rebind_symbols is null");
        }

        if (rebind_symbols_image == null) {
            throw new IllegalStateException("rebind_symbols_image is null");
        }
    }

    @Override
    public void rebindSymbol(String symbol, ReplaceCallback callback) {
        Pointer rebinding = createRebinding(symbol, callback);
        int ret = rebind_symbols.call(emulator, rebinding, 1)[0].intValue();
        if (ret != RET_SUCCESS) {
            throw new IllegalStateException("ret=" + ret);
        }
    }

    private Pointer createRebinding(String symbol, ReplaceCallback callback) {
        Memory memory = emulator.getMemory();
        Pointer symbolPointer = memory.malloc(symbol.length() + 1, false).getPointer();
        symbolPointer.setString(0, symbol);

        final Pointer originCall = memory.malloc(emulator.getPointerSize(), false).getPointer();
        Pointer replaceCall = createReplacePointer(callback, originCall);

        Pointer rebinding = memory.malloc(emulator.getPointerSize() * 3, false).getPointer();
        rebinding.setPointer(0, symbolPointer);
        rebinding.setPointer(emulator.getPointerSize(), replaceCall);
        rebinding.setPointer(2 * emulator.getPointerSize(), originCall);
        return rebinding;
    }

    @Override
    public void rebindSymbolImage(MachOModule module, String symbol, ReplaceCallback callback) {
        long header = module.machHeader;
        long slide = Dyld.computeSlide(emulator, header);
        Pointer rebinding = createRebinding(symbol, callback);
        int ret = rebind_symbols_image.call(emulator, UnicornPointer.pointer(emulator, header), UnicornPointer.pointer(emulator, slide), rebinding, 1)[0].intValue();
        if (ret != RET_SUCCESS) {
            throw new IllegalStateException("ret=" + ret);
        }
    }

}
