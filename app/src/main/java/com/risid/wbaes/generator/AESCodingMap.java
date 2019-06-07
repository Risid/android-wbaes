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


import com.risid.wbaes.AES;
import com.risid.wbaes.State;

/**
 * Stores information for connecting IO encodings together 
 * in WB AES implementation.
 * 在WB AES实现过程中存储连接IO编码的信息
 *
 * @author ph4r05
 */
public class AESCodingMap {					      // 15*4*8, used with T1 tables
    public static final int BYTES  = AES.BYTES;
    public static final int ROUNDS = AES.ROUNDS;
    public static final int T1BOXES = AES.T1BOXES;
    public static final int T1Boxes = AES.T1Boxes;

    private GTBox8to128[][]    t1        = null;
    private GXORCascadeState[] xorState  = null;
    private GTBox8to32[][]     t2        = null;
    private GTBox8to32[][]     t3        = null;
    private GXORCascade[][]    xor       = null;
    private boolean            encrypt   = true;
    private int                idx       = 0;

    public static int transpose(int idx){
        return State.transpose(idx);
    }

    public int shiftOp(int idx){
        return AES.shift(idx, !encrypt);
    }

    /**
     * Memory allocation of each box
     * 各盒的内存分配
     */
    public void init(){
        int i,r;

        t1        = new GTBox8to128[T1BOXES][BYTES];
        xorState  = new GXORCascadeState[T1BOXES];
        t2        = new GTBox8to32[ROUNDS][BYTES];
        t3        = new GTBox8to32[ROUNDS][BYTES];
        xor       = new GXORCascade[ROUNDS][2*State.COLS];

        for(r=0; r<ROUNDS; r++){
            //
            // XOR state cascade
            //
            // 异或状态级联
            if (r<T1BOXES){
                xorState[r] = new GXORCascadeState();
            }

            for(i=0; i<BYTES; i++){

                //
                // T1 boxes
                //
                // T1盒
                if (r<T1BOXES){
                    t1[r][i] = new GTBox8to128();
                }

                //
                // T2, T3 boxes
                //
                // T2, T3盒
                t2[r][i] = new GTBox8to32();
                t3[r][i] = new GTBox8to32();

                //
                // XOR cascade
                //
                // 异或级联
                if (i < 2*State.COLS){
                    xor[r][i] = new GXORCascade();
                }
            }
        }
    }

    /**
     * generate coding map for AES for IO bijections
     * 为IO双射的AES生成编码映射
     */
    public void generateCodingMap(){
        int i,j,r;
        this.idx = 0;

        // At first allocate new bijections for T1 output tables
        // 首先为T1输出表分配新的仿射变换
        // Allocate encodings for XOR cascade summing output of T1 boxes
        // 为T1盒的XOR级联求和输出分配编码
        for(r=0; r<2; r++){
            // Allocate bijections for T1 boxes
            // 为T1盒分配仿射变换
            for(i=0; i<BYTES; i++){
                idx = t1[r][i].allocate(idx);
            }

            // Allocate XOR cascade state bijections
            // 分配XOR级联状态仿射变换
            // XOR table cascade for T1 out sum, 8,4,2,1 = 15 XOR tables
            // T1输出和的XOR表级联，8,4,2,1=15 XOR表
            // Caution! Last 128-bit XOR table from T1[1] is output from whole cipher -> no allocation for this
            // 注意！T1[1]的最后一个128位XOR表是从整个密码输出的，故不用分配
            idx = xorState[r].allocate(idx, r==0);

            // Connecting part
            // 连接
            xorState[r].connectInternal();
            for(i=0; i<BYTES; i++){
                t1[r][i].connectOut(xorState[r], i);
            }
        }

        // Now connect XOR3 tables form R=0 (sums T1 input table) to input of T2 tables
        // 将XOR3表从R=0（即T1盒输出和）连接到T2表的输出
        // Result is stored in last XOR table starting on 448 offset, result is stored in LOW value
        // 结果存储在最后一个XOR表中，偏移量448，低位存放
        //
        // Note that ShiftRows is done here, every Sbox uses result of ShiftRows operation on its input
        // 这里完成ShiftRows的操作，每个S盒对其输入使用ShiftRows的运算结果
        //
        // 128-bit XOR has output indexed by rows, same as state.
        //
        for(i=0; i<BYTES; i++){
            int newIdx = shiftOp(i);
            xorState[0].connectOut(t2[0][newIdx], i);
        }

        //
        // In the last round there is only T1 table, with defined output mapping by user (external)
        // 在上一轮中，只有T1表，由用户定义输出映射（外部）
        // so it is not allocated here. There are no XOR tables and T3 tables in 10. round.
        // 所以它没有参与接下来的代码分配。第10轮操作不含XOR表和T3表，
        //
        // Thus encode only round 1..9.
        // 故仅对1到9轮进行编码
        // Last round 9 output coding from XOR2 master table
        // XOR2主表由第9轮输出编码
        //
        // is connected to T1[1] input coding in round 10.
        // 与第10轮的T1[1]输入编码相连
        //
        for(r=0; r<(ROUNDS-1); r++){
            //
            // Allocation part, OUTPUT direction creates/defines new mapping
            // 分配在输出方向创建/定义新映射的内存
            //
            for(i=0; i<BYTES; i++){
                idx = t2[r][i].allocate(idx);
                idx = t3[r][i].allocate(idx);
                if (i < 2*State.COLS){
                    idx = xor[r][i].allocate(idx);
                }
            }

            // iterate over strips/MC cols
            // 迭代
            for(i=0; i<BYTES; i++){
                //
                // Connecting part - connecting allocated codings together
                // 连接已分配的编码
                //
                final int xorCol1 = 2*(i % State.COLS);     //2*(i/State.COLS);
                final int xorCol2 = 2*(i % State.COLS) + 1; //2*(i/State.COLS) + 1;
                final int slot    =    i / State.COLS;

                // Connect T2 boxes to XOR input boxes
                // 连接T2盒到XOR输出盒
                t2[r][i].connectOut(xor[r][xorCol1], slot);

                // XOR boxes, one per column
                // XOR盒，每列一个
                if ((i / State.COLS) == (State.ROWS-1)){
                    // Connect XOR layer 1 to XOR layer 2
                    // 连接XOR的第1层到第2层
                    xor[r][xorCol1].connectInternal();
                }

                // Connect result XOR layer 2 to B boxes (T3)
                // 将结果XOR第2层连接到B盒（即T3盒）
                xor[r][xorCol1].connectOut(t3[r][i], slot);

                // Connect B boxes to XOR
                // 将B盒连接到XOR
                t3[r][i].connectOut(xor[r][xorCol2], slot);

                // Connect XOR layer 3 to XOR layer 4
                // 连接XOR的第3层到第4层
                if ((i / State.COLS) == (State.ROWS-1)){
                    xor[r][xorCol2].connectInternal();
                }

                if (r<(ROUNDS-2)){
                    // Connect result XOR layer 4 to T2 boxes in next round
                    // 在下一轮中，将结果XOR的第4层连接到T2盒
                    xor[r][xorCol2].connectOut(t2[r+1][shiftOp(i)], slot);
                } else {
                    // Connect result XOR layer 4 to T1 boxes in last round; r==8
                    // 在最后一轮中，将结果XOR的第4层连接到T1盒；当r==8的时候运行
                    xor[r][xorCol2].connectOut(t1[1][shiftOp(i)], slot);
                }
            }
        }
    }

    public GTBox8to128[][] getT1() {
        return t1;
    }

    public GXORCascadeState[] getXorState() {
        return xorState;
    }

    public GTBox8to32[][] getT2() {
        return t2;
    }

    public GTBox8to32[][] getT3() {
        return t3;
    }

    public GXORCascade[][] getXor() {
        return xor;
    }

    public boolean isEncrypt() {
        return encrypt;
    }

    public int getIdx() {
        return idx;
    }

    public void setEncrypt(boolean encrypt) {
        this.encrypt = encrypt;
    }
}
