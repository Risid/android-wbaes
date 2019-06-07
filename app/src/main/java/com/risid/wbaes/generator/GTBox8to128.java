/*
 * Copyright (c) 2014, Dusan (Ph4r05) Klinec, Petr Svenda
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * * Neither the name of the copyright holders nor the names of
 *   its contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package com.risid.wbaes.generator;

import com.risid.wbaes.generator.Generator.W08x128Coding;

/**
 *
 * @author ph4r05
 */
public class GTBox8to128 implements IOEncoding {
    protected W08x128Coding cod;
    
    public GTBox8to128() {
        super();
        cod = new W08x128Coding();
    }
    
    /**
     * Allocates IO encodings.
     * 分配IO编码
     * @param idx
     * @return 
     */
    public final int allocate(int idx){
        idx = Generator.ALLOCW08x128Coding(cod, idx);
        return idx;
    }
    
    /**
     * Connects output of this box to input of XOR cascade.
     * Slot gives particular input slot in XOR cascade. Slots: [0-15]
     *
     * 将此盒的输出连接到XOR级联的输入。
     * Slot在XOR级联中给出特定的输入槽。Slot：[0-15]
     * TODO: FINISH IMPLEMENTATION!
     * @param c
     * @param slot 
     */
    public void connectOut(GXORCascadeState c, int slot){
        Generator.XORCODING[] xcod = c.getCod();
        for(int i=0; i<4; i++){
            Generator.CONNECT_W08x32_TO_XOR_EX(cod, xcod[slot/2], (slot%2) == 0, i*8, i*4);
        }
    }
    
    public W08x128Coding getCod() {
        return cod;
    }
    
    public int getIOInputWidth() {
        return 1;
    }

    public int getIOOutputWidth() {
        return 16;
    }

    public int getIOInputSlots() {
        return 1;
    }
    
    
}
