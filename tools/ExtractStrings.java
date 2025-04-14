import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import java.io.*;

public class ExtractStrings extends GhidraScript {
    @Override
    protected void run() throws Exception {
        // 創建輸出文件
        File outputFile = new File(currentProgram.getName() + "_strings.txt");
        try (PrintWriter writer = new PrintWriter(outputFile)) {
            // 獲取所有字符串
            Memory memory = currentProgram.getMemory();
            for (MemoryBlock block : memory.getBlocks()) {
                if (block.isInitialized()) {
                    byte[] bytes = new byte[(int) block.getSize()];
                    memory.getBytes(block.getStart(), bytes);
                    
                    // 提取 ASCII 字符串
                    extractAsciiStrings(bytes, block.getStart(), writer);
                }
            }
        }
    }
    
    private void extractAsciiStrings(byte[] bytes, long startAddress, PrintWriter writer) {
        StringBuilder currentString = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (bytes[i] >= 32 && bytes[i] <= 126) {  // 可打印 ASCII
                currentString.append((char) bytes[i]);
            } else if (currentString.length() >= 4) {  // 最小字符串長度
                writer.println(String.format("0x%X: %s", startAddress + i - currentString.length(), currentString.toString()));
                currentString.setLength(0);
            } else {
                currentString.setLength(0);
            }
        }
    }
} 