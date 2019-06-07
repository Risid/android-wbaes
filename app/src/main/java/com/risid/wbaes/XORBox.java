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
package com.risid.wbaes;

import java.io.Serializable;
import java.util.Arrays;

/**
 * Represents (32, 32) -> 32 bit XOR box for whitebox transformation.
 * Holds XOR tables and performs operation. Only for whitebox runtime,
 * not for design.
 * 代表（32,32） - > 32位XOR盒用于白盒转换。
 * 拥有XOR表并执行操作。 仅适用于白盒运行时，不适用于设计
 * 
 * Short & simple methods are good candidates for inlining.
 * 简短的方法是内联的理想选择
 * @see {ftp://ftp.glenmccl.com/pub/free/jperf.pdf}
 * 
 * @author ph4r05
 */
public class XORBox implements Serializable{
    public static final int WIDTH = 4;
    // 输入大小为1的盒是4位
    public static final int BOXES = WIDTH*2;    // input size of 1 box is 4 bits
    
    // Main XOR table 
    // represents eight 8 -> 4 bit XOR tables
    // 主XOR表
    // 代表八个8 - >4位XOR表
    protected byte[][] xor = null;
    
    /**
     * Empty constructor
     * 空构造函数
     */
    public XORBox() {
        init();
    }
    
    /**
     * XOR box constructor with initialized xor table.
     * 带有初始化xor表的XOR盒构造函数
     * @param xorTbl
     * @param copy 
     */
    public XORBox(final byte[][] xorTbl, boolean copy) {
        setXor(xorTbl, copy);
    }
    
    /**
     * Performs XOR on two 32 bit operands a,b.
     * 在两个32位操作数a，b上执行XOR
     * @param a
     * @param b
     * @return 
     */
    public long xor(long a, long b){
        return xor(xor, a, b);
    }
    
    /**
     * Performs XOR on two 32 bit operands a,b. Uses provided XOR table.
     * 在两个32位操作数a，b上执行XOR。 使用提供的XOR表。
     * @param a
     * @param b
     * @return 
     */
    public static long xor(final byte[][] xor, long a, long b){
        long result = 0;
        for (int i=0; i<BOXES; i++){
            result |= ((long)(xor[i][ (int) ((((a >>> (i*4)) & 0xF) << 4) | (b >>> (i*4)) & 0xF) ])) << (i*4);
        }
        
        return result;
    }
    
    /**
     * Performs XOR on two 32 bit operands a,b, result is put to a.
     * 在两个32位操作数a，b上执行XOR，结果放到a
     * @param a
     * @param b
     * @return 
     */
    public byte[] xorA(byte[] a, byte[] b){
        return xorA(xor, a, b);
    }
    
    /**
     * Performs XOR on two 32 bit operands a,b, result is put to a.
     * Uses provided XOR table.
     * 在两个32位操作数a，b上执行XOR，结果放到a。
     * 使用提供的XOR表。
     *
     * @param a
     * @param b
     * @return 
     */
    public static byte[] xorA(final byte[][] xor, byte[] a, byte[] b){
        for (int i=0; i<WIDTH; i++){
            a[i] = (byte)( 
                    (xor[2*i+0][(((a[i] >>> 4) & 0xF) << 4) | ((b[i] >>> 4) & 0xF)] << 4)
                  | (xor[2*i+1][(( a[i]        & 0xF) << 4) | ( b[i]        & 0xF)]     ) 
                   );
        }
        
        return a;
    }

    /**
     * Sets XOR box internal table
     * 设置XOR盒内部表
     *
     * @param xorTbl
     * @param copy      - if yes array is copied 是否拷贝
     */
    public final void setXor(final byte[][] xorTbl, boolean copy){
        if (xorTbl.length != BOXES) {
            throw new IllegalArgumentException("XOR table has to have 8 sub-tables");
        }
        
        if (copy){
            xor = new byte[BOXES][];
            for (int i=0; i < BOXES; i++) {
                xor[i] = Arrays.copyOf(xorTbl[i], 256);
            }
        } else {
            this.xor = xorTbl;
        }
    }
    
    /**
     * Sets XOR box internal table
     * 设置XOR盒内部表
     * @param xorTbl 
     */
    public void setXor(final byte[][] xorTbl){
        setXor(xorTbl, true);
    }
    
    /**
     * Sets 1 sub-table in XOR table with 8 rows.
     * 在XOR表中设置1个具有8行的子表。
     *
     * @param xorTbl
     * @param idx
     * @param copy 
     */
    public final void setPartXor(final byte[] xorTbl, final int idx, final boolean copy){
        if (xorTbl.length != 256) {
            throw new IllegalArgumentException("XOR table has to have 256 rows");
        }
        
        if (xor == null){
            throw new NullPointerException("Internal table is completely null, initialize xor table");
        }
        
        if (copy){     
            xor[idx] = Arrays.copyOf(xorTbl, 256);
        } else {
            this.xor[idx] = xorTbl;
        }
    }
    
    /**
     * Sets 1 sub-table in XOR table with 8 rows.
     * 在XOR表中设置1个具有8行的子表。
     * @param xorTbl
     * @param idx
     * @param copy 
     */
    public void setPartXor(final byte[] xorTbl, final int idx){
        setPartXor(xorTbl, idx, true);
    }
    
    /**
     * Initializes XOR tables - memory allocation
     * 初始化XOR表 - 具有8行的内存分配
     *
     */
    public final void init(){
        xor = new byte[BOXES][256];
    }

    public static int getWidth() {
        return WIDTH;
    }

    public static int getBoxes() {
        return BOXES;
    }

    public byte[][] getTbl() {
        return xor;
    }
    
    @Override
    public int hashCode() {
        int hash = 7;
        hash = 53 * hash + Arrays.deepHashCode(this.xor);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final XORBox other = (XORBox) obj;
        if (!Arrays.deepEquals(this.xor, other.xor)) {
            return false;
        }
        return true;
    }
}
