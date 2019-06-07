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
 * Main AES whitebox table implementation.
 * AES白盒表实现
 * @author ph4r05
 */
public class AES implements Serializable {
    public static final int BYTES  = State.BYTES;
    public static final int ROUNDS = 10;
    public static final int T1BOXES = 2;
    public static final int T1Boxes = 2;
    public static final int shiftRows[] = {
            0,   1,  2,  3,
            5,   6,  7,  4,
            10, 11,  8,  9,
            15, 12, 13, 14
    };

    public static final int shiftRowsInv[] = {
            0,  1,  2,  3,
            7,  4,  5,  6,
            10, 11,  8,  9,
            13, 14, 15, 12
    };

    protected T1Box[][]         t1       = new T1Box[T1BOXES][State.BYTES];
    protected XORCascadeState[] xorState = new XORCascadeState[T1BOXES];
    protected T2Box[][]         t2       = new T2Box[ROUNDS][State.BYTES];
    protected T3Box[][]         t3       = new T3Box[ROUNDS][State.BYTES];
    protected XORCascade[][]    xor      = new XORCascade[ROUNDS][2* State.COLS];
    private boolean           encrypt  = true;

    public static int posIdx(byte x){
        return x & 0xff;
    }

    public static int posIdx(int x){
        return x & 0xff;
    }

    /**
     * Encryption OR decryption - depends on generated tables
     * 加密或解密 - 取决于生成的表
     * @param in
     */
    public State crypt(State state){
        int r=0, i=0;
        // T2，T3盒的中间结果
        W32b  ires[] = new W32b[BYTES];	// intermediate result for T2,T3-boxes
        // T1盒的中间结果
        State ares[] = new State[BYTES];	// intermediate result for T1-boxes

        // initialize ires, ares at first
        // 初始化ires，ares
        for(i=0; i<BYTES; i++){
            ires[i] = new W32b();
            ares[i] = new State();
        }

        // At first we have to put input to T1 boxes directly, no shift rows
        // compute result to ares[16]
        // 首先，直接将输入流入T1盒，没有行移位。
        // 计算结果存入ares[16]
        for(i=0; i<BYTES; i++){
            // Note: Tbox is indexed by cols, state by rows - transpose needed here
            // 注意：T盒由列索引，而状态数组是按行 - 需要转置
            ares[i].loadFrom( t1[0][i].lookup(state.get(i)) );
        }

        // now compute XOR cascade from 16 x 128bit result after T1 application.
        // 在T1之后，从16 x 128bit结果计算XOR级联
        xorState[0].xor(ares);
        state.loadFrom(ares[0]);

        // Compute 9 rounds of T2 boxes
        // 使用T2盒计算9轮
        for(r=0; r<ROUNDS-1; r++){
            // Apply type 2 tables to all bytes, counting also shift rows selector.
            // One section ~ 1 column of state array, so select 1 column, first will
            // have indexes 0,4,8,12. Also take ShiftRows() into consideration.
            // 将二型表应用于所有字节，计算行移位选择器
            // 一段的第1列为状态数组，因此选择1列
            // 首先索引0,4,8,12，还要考虑ShiftRows()
            //
            for(i=0; i<BYTES; i++){
                ires[i].set(t2[r][i].lookup(state.get(shift(i))));
            }

            for(i=0; i< State.COLS; i++){
                // XOR results for one column from T2 boxes.
                // XOR结果来自T2盒的一列
                // After this operation we will have one 32bit ires[] for 1 column
                // 在此操作之后，得到有一列数据的32位ires[]
                ires[i].set(xor[r][2*i].xor(
                        ires[ 0+i].getLong(),
                        ires[ 4+i].getLong(),
                        ires[ 8+i].getLong(),
                        ires[12+i].getLong()));

                // Apply T3 boxes, valid XOR results are in ires[0], ires[4], ires[8], ires[12]
                // Start from the end, because in ires[i] is our XORing result.
                // 计算T3盒，XOR结果在ires [0]，ires [4]，ires [8]，ires [12]
                // 从后往前，因为在ires中[i]是异或之后的结果
                final byte[] cires = ires[i].get();
                ires[12+i].set(t3[r][12+i].lookup(cires[3]));
                ires[ 8+i].set(t3[r][ 8+i].lookup(cires[2]));
                ires[ 4+i].set(t3[r][ 4+i].lookup(cires[1]));
                ires[ 0+i].set(t3[r][ 0+i].lookup(cires[0]));

                // Apply final XOR cascade after T3 box
                // 在T3盒之后计算最后XOR级联
                ires[i].set(xor[r][2*i+1].xor(
                        ires[ 0+i].getLong(),
                        ires[ 4+i].getLong(),
                        ires[ 8+i].getLong(),
                        ires[12+i].getLong()));

                // Copy results back to state,
                // valid XOR results are in 32bit ires[0], ires[4], ires[8], ires[12]
                // 复制结果到状态数组，合法的异或结果在ires[0], ires[4], ires[8], ires[12]内
                state.setColumn(ires[i], i);
            }
        }

        //
        // Final round is special -> T1 boxes
        // 最后一轮T1盒
        //
        for(i=0; i<BYTES; i++){
            // Note: Tbox is indexed by cols, state by rows - transpose needed here
            // 注意：T盒由列索引，而状态数组是按行 - 需要转置
            ares[i].loadFrom( t1[1][i].lookup(state.get(shift(i))) );
        }

        // now compute XOR cascade from 16 x 128bit result after T1 application.
        // 在T1之后，从16 x 128bit结果计算XOR级联
        xorState[1].xor(ares);
        state.loadFrom(ares[0]);

        return state;
    }

    /**
     * Returns needed shift operation according to cipher direction (enc vs. dec).
     * 根据是加密或解密，返回所需的移位操作。
     * @param encrypt
     * @return
     */
    public static int[] getShift(boolean encrypt){
        return encrypt ? shiftRows : shiftRowsInv;
    }

    /**
     * Returns shifted bit
     * 返回移位
     *
     * @param idx
     * @param encrypt
     * @return
     */
    public static int shift(int idx, boolean encrypt){
        return getShift(encrypt)[idx];
    }

    /**
     * Returns shifted bit 
     * 返回移位
     * @param idx
     * @param encrypt
     * @return
     */
    public int shift(int idx){
        return getShift(encrypt)[idx];
    }


    /**
     * Memory allocation of each box
     * 每个盒的内存分配
     */
    public void init(){
        int i,r;

        t1        = new T1Box[T1BOXES][BYTES];
        xorState  = new XORCascadeState[T1BOXES];
        t2        = new T2Box[ROUNDS][BYTES];
        t3        = new T3Box[ROUNDS][BYTES];
        xor       = new XORCascade[ROUNDS][2* State.COLS];

        for(r=0; r<ROUNDS; r++){
            //
            // XOR state cascade
            // XOR状态级联
            //
            if (r<T1BOXES){
                xorState[r] = new XORCascadeState();
            }

            for(i=0; i<BYTES; i++){

                //
                // T1 boxes
                // T1盒
                //
                if (r<T1BOXES){
                    t1[r][i] = new T1Box();
                }

                //
                // T2, T3 boxes
                // T2,T3盒
                //
                t2[r][i] = new T2Box();
                t3[r][i] = new T3Box();

                //
                // XOR cascade
                // XOR级联
                //
                if (i < 2* State.COLS){
                    xor[r][i] = new XORCascade();
                }
            }
        }
    }

    public T1Box[][] getT1() {
        return t1;
    }

    public XORCascadeState[] getXorState() {
        return xorState;
    }

    public T2Box[][] getT2() {
        return t2;
    }

    public T3Box[][] getT3() {
        return t3;
    }

    public XORCascade[][] getXor() {
        return xor;
    }

    public boolean isEncrypt() {
        return encrypt;
    }

    public void setEncrypt(boolean encrypt) {
        this.encrypt = encrypt;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 89 * hash + Arrays.deepHashCode(this.t1);
        hash = 89 * hash + Arrays.deepHashCode(this.xorState);
        hash = 89 * hash + Arrays.deepHashCode(this.t2);
        hash = 89 * hash + Arrays.deepHashCode(this.t3);
        hash = 89 * hash + Arrays.deepHashCode(this.xor);
        hash = 89 * hash + (this.encrypt ? 1 : 0);
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
        final AES other = (AES) obj;
        if (!Arrays.deepEquals(this.t1, other.t1)) {
            return false;
        }
        if (!Arrays.deepEquals(this.xorState, other.xorState)) {
            return false;
        }
        if (!Arrays.deepEquals(this.t2, other.t2)) {
            return false;
        }
        if (!Arrays.deepEquals(this.t3, other.t3)) {
            return false;
        }
        if (!Arrays.deepEquals(this.xor, other.xor)) {
            return false;
        }
        if (this.encrypt != other.encrypt) {
            return false;
        }
        return true;
    }
}
