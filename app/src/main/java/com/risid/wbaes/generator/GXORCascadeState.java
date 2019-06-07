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

import com.risid.wbaes.XORBoxState;
import com.risid.wbaes.XORCascadeState;
import com.risid.wbaes.generator.Generator.XORCODING;

/**
 *
 * @author ph4r05
 */
public class GXORCascadeState implements IOEncoding {
    protected XORCODING cod[];
    protected Bijection4x4[] extCoding = null; // length = XORBoxState.BOXES;
    protected boolean outputUnallocated = true;
    
    public GXORCascadeState() {
        super();
        cod = new XORCODING[XORCascadeState.BOXES];
        for(int i = 0; i< XORCascadeState.BOXES; i++){
            cod[i] = new XORCODING(2* XORCascadeState.WIDTH);
        }
    }

    public GXORCascadeState(XORCODING[] cod) {
        this.cod = cod;
    }
    
    /**
     * Allocates XOR cascade coding.
     * @param idx
     * @param allocateOutput  tells whether to allocate output bijections for 
     *      last XOR stage - output from XORCascadeState. Used as output from 
     *      ciper - external encodings are used.
     * @return 
     */
    public final int allocate(int idx, boolean allocateOutput){
        this.outputUnallocated = !allocateOutput;
        for(int i = 0; i< XORCascadeState.BOXES; i++){
            if (!allocateOutput && (i+1) == XORCascadeState.BOXES) {
                break;
            }
            
            idx = Generator.ALLOCXORCoding(cod[i], 0, idx, 2* XORCascadeState.WIDTH);
        }
        
        return idx;
    }
    
    /**
     * Allocates XOR cascade coding.
     * @param idx
     * @return 
     */
    public final int allocate(int idx){
        return allocate(idx, true);
    }
    
    /**
     * Connect cascade from the inside.
     * Connects layer 1 to layer 2 in XOR component.
     * 
     */
    public final void connectInternal(){        
         // offset in x[] for current stage
        int XORoffset = 0;  
        // j is XOR stage number
        for(int j=0; j<3; j++){
            // Number of iterations in each stage is 8,4,2,1. i.e. 2^3, 2^2, 2^1, 2^0
            final int iterationsInStage = 1 << (3-j);
            // Step of XORing neighbouring states in one stage; 1st: 0+1, 2+3,...; 2nd: 0+2, 2+4,...; 3rd 0+4,...
            final int xorBoxStep        = 1 <<    j;  
            // performing XOR inside one 
            for(int i=0; i<iterationsInStage; i+=2){
                // Position to state[] for current stage
                Generator.CONNECT_XOR_TO_XOR_128_H(cod[XORoffset + i+0], 0, cod[XORoffset + iterationsInStage + i/2], 0);
                Generator.CONNECT_XOR_TO_XOR_128_L(cod[XORoffset + i+1], 0, cod[XORoffset + iterationsInStage + i/2], 0);
            }
            
            XORoffset += iterationsInStage;
        }
    }
    
    /**
     * Connects output of this box to input of 8bit table.
     * Slot gives particular output slot in XOR cascade.
     * 
     * @param c
     * @param slot 
     */
    public void connectOut(GTBox8to32 c, int slot){
        Generator.W08x32Coding cod1 = c.getCod();
        Generator.CONNECT_XOR_TO_W08x32(cod[XORCascadeState.BOXES-1], 2*slot, cod1);
    }
    
    /**
     * Sets external encoding for output XOR box.
     * @param ext 
     */
    public void setExternalOut(Bijection4x4[] ext){
        this.extCoding = ext;
    }
    
    /**
     * Generates XOR tables for particular XOR cascade.
     * 
     * @param c
     * @param g 
     */
    public void generateTables(XORCascadeState c, Generator g){
        final Bijection4x4[] pCoding04x04 = g.getIo().getpCoding04x04();
        XORBoxState[] x = c.getX();
        
        // Iterate over each 128bit XOR box
        for(int i = 0; i< XORCascadeState.BOXES; i++){
            // Get whole XOR table; tbl[XORBox.BOXES][256]
            byte[][] tbl = x[i].getTbl();
            for(int j=0; j<XORBoxState.BOXES; j++){
                Generator.generateXorTable(cod[i].xtb[j], tbl[j], pCoding04x04);
                
                // Do we have some special external encoding here to use ?
                if (outputUnallocated && (i+1) == XORCascadeState.BOXES && extCoding != null){
                    for(int k=0; k<256; k++){
                        tbl[j][k] = extCoding[j].coding[tbl[j][k]];
                    }
                }
            }
        }
    }

    public XORCODING[] getCod() {
        return cod;
    }

    public int getIOInputWidth() {
        return XORCascadeState.WIDTH;
    }

    public int getIOOutputWidth() {
        return XORCascadeState.WIDTH;
    }

    public int getIOInputSlots() {
        return XORCascadeState.WIDTH;
    }
}
