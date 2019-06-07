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

import com.risid.wbaes.XORBox;
import com.risid.wbaes.XORCascade;
import com.risid.wbaes.generator.Generator.W08x128Coding;
import com.risid.wbaes.generator.Generator.W08x32Coding;
import com.risid.wbaes.generator.Generator.XORCODING;

/**
 *
 * @author ph4r05
 */
public class GXORCascade implements IOEncoding{
    public static final int XOR_BOXES = XORCascade.BOXES;
    protected XORCODING cod[];
    
    public GXORCascade() {
        super();
        cod = new XORCODING[XOR_BOXES];
        cod[0] = new XORCODING(XORBox.BOXES);
        cod[1] = new XORCODING(XORBox.BOXES);
        cod[2] = new XORCODING(XORBox.BOXES);
    }
    
    /**
     * Allocates XOR cascade coding.
     * 分配XOR级联编码
     * @param idx
     * @return 
     */
    public final int allocate(int idx){
        idx = Generator.ALLOCXORCoding(cod[0], 0, idx, XORBox.BOXES);
        idx = Generator.ALLOCXORCoding(cod[1], 0, idx, XORBox.BOXES);
        idx = Generator.ALLOCXORCoding(cod[2], 0, idx, XORBox.BOXES);
        return idx;
    }
    
    /**
     * Connect cascade from the inside.
     * Connects layer 1 to layer 2 in XOR component.
     * 从内部连接级联
     * 在XOR组件中将第1层连接到第2层
     */
    public final void connectInternal(){        
        // Connect output from two XOR boxes to input of one XOR box
        // 将两个XOR框的输出连接到一个XOR框的输入
        Generator.CONNECT_XOR_TO_XOR_H(cod[0], 0, cod[2], 0);
        Generator.CONNECT_XOR_TO_XOR_L(cod[1], 0, cod[2], 0);
    }

    /**
     * Connects output of this box to input of 8bit table.
     * Slot gives particular output slot in XOR cascade.
     * 将此盒的输出连接到8位表的输入
     * Slot在XOR级联中提供特定的输出槽
     * 
     * @param c
     * @param slot 
     */
    public void connectOut(GTBox8to32 c, int slot){
        W08x32Coding cod1 = c.getCod();
        Generator.CONNECT_XOR_TO_W08x32(cod[XORCascade.BOXES-1], 2*slot, cod1);
    }
    
    /**
     * Connects output of this box to input of 8bit table.
     * Slot gives particular output slot in XOR cascade.
     * 将此盒的输出连接到8位表的输入
     * Slot在XOR级联中提供特定的输出槽
     *
     * @param c
     * @param slot 
     */
    public void connectOut(GTBox8to128 c, int slot){
        W08x128Coding cod1 = c.getCod();
        Generator.CONNECT_XOR_TO_W08x32(cod[XORCascade.BOXES-1], 2*slot, cod1);
    }
    
    /**
     * Generates XOR tables for particular XOR cascade.
     * 为特定的XOR级联生成XOR表
     *
     * @param c
     * @param g 
     */
    public void generateTables(XORCascade c, Generator g){
        final Bijection4x4[] pCoding04x04 = g.getIo().getpCoding04x04();
        XORBox[] x = c.getX();
        
        // Iterate over each 32bit XOR box
        // 迭代每个32位XOR盒
        for(int i=0; i<XOR_BOXES; i++){
            // Get whole XOR table; tbl[XORBox.BOXES][256]
            // 获取整个XOR表;TBL[XORBox.BOXES] [256]
            byte[][] tbl = x[i].getTbl();
            for(int j=0; j<XORBox.BOXES; j++){
                Generator.generateXorTable(cod[i].xtb[j], tbl[j], pCoding04x04);
            }
        }
    }
    
    public XORCODING[] getCod() {
        return cod;
    }

    public int getIOInputWidth() {
        return XORCascade.WIDTH;
    }

    public int getIOOutputWidth() {
        return XORCascade.WIDTH;
    }

    public int getIOInputSlots() {
        return XORCascade.WIDTH;
    }
    
}
