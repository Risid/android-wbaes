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
 * AES-128 State
 * AES-128状态数组
 * @author ph4r05
 */
public class State implements Serializable, Copyable{
    public static final int BYTES = 16;
    public static final int ROWS  = 4;
    public static final int COLS  = BYTES / ROWS;
    protected byte[] state;
    protected boolean immutable=false;

    /**
     * Default constructor, allocates memory for internal state representation.
     * 默认构造函数，为内部状态表示分配内存
     */
    public State() {
        init();
    }

    /**
     * Uses given byte[] as internal representation, no copy.
     * 使用给定的byte []作为内部表示，无拷贝
     * @param state 
     */
    public State(byte[] state) {
        this.state = state;
    }
    
    /**
     * Copy/assign constructor.
     * 拷贝或分配构造函数
     * @param state
     * @param copy 
     */
    public State(byte[] state, boolean copy) {
        if (copy){
            this.state = Arrays.copyOf(state, BYTES);
        } else {
            this.state = state;
        }
    }
    
    /**
     * Copy/assign constructor. Can transpose input bytes - AES input state
     * is loaded by columns.
     * 拷贝/分配构造函数。 可以转置输入字节 -  AES输入状态由列加载
     * @param state
     * @param copy 
     * @param transpose    transpose, copy is forced
     */
    public State(byte[] state, boolean copy, boolean transpose) {
        if (transpose==false){
            if (copy){
                this.state = Arrays.copyOf(state, BYTES);
            } else {
                this.state = state;
            }
        } else {
            init();
            for(int i=0; i<BYTES; i++){
                this.state[i] = state[transpose(i)];
            }
        }
    }
    
    /**
     * Sets whole vector to zero.
     * 将整个向量设置为零
     */
    public void zero(){
        Arrays.fill(this.state, (byte)0);
    }
    
    /**
     * Per-byte state getter.
     * 每字节状态的获取器
     * @param idx
     * @return 
     */
    public byte get(int idx){
        if (idx<0 || idx >= BYTES){
            throw new IllegalArgumentException("Invalid byte requested");
        }
        
        return this.state[idx];
    }
    
    /**
     * Per-byte state setter.
     * 每字节状态设置器
     * @param b
     * @param idx 
     */
    public void set(byte b, int idx){
        if (idx<0 || idx >= BYTES) {
            throw new IllegalArgumentException("Invalid byte requested");
        }
        
        if (state == null){
            throw new NullPointerException("State is not initialized");
        }
        
        if (immutable){
            throw new IllegalAccessError("State is set as immutable, cannot change");
        }
        
        this.state[idx] = b;
    }
    
    /**
     * Returns index to byte array for 2D coordinates, indexed by rows (0 1 2 3)
     * 返回2D坐标的字节数组的索引，由行索引（0 1 2 3）
     * @param i
     * @param j
     * @return 
     */
    public static int getIdx(int i, int j){
        return i*COLS + j;
    }
    
    /**
     * Returns index to byte array for 2D coordinates, indexed by cols (0 4 8 12)
     * 返回索引字节数组的二维坐标，通过COLS（0 4 8 12）索引
     * @param i
     * @param j
     * @return 
     */
    public static int getCIdx(int i, int j){
        return j*ROWS + i;
    }
    
    /**
     * Returns transposed index for matrix
     * 返回矩阵的转置索引
     *  00 01 02 03        00 04 08 12
     *  04 05 06 07        01 05 09 13
     *  08 09 10 11  --->  02 06 10 14
     *  12 13 14 15        03 07 11 15
     * 
     * @param idx
     * @return 
     */
    public static int getTIdx(int idx){
        return getCIdx(idx / COLS, idx % ROWS);//  4*((idx)%4) + ((idx)/4);
    }
    
    /**
     * Transpose 4x4 index for state matrix.
     * 为状态矩阵转置4x4索引
     * 
     * @param idx
     * @return 
     */
    public static int transpose(int idx){
        return (idx / COLS) + ROWS * (idx % ROWS);
    }
    
    /**
     * Getter for 2D coordinates, assuming first line indexing: 0 1 2 3
     * 2D坐标的获取器，假设第一行索引: 0 1 2 3
     * @param i row
     * @param j column
     * @return 
     */
    public byte get(int i, int j){
        return get(getIdx(i, j));
    }
    
    /**
     * Getter for 2D coordinates, assuming first line indexing: 0 4 8 12
     * 2D坐标的获取器，假设第一行索引:0 4 8 12
     * @param i row
     * @param j column
     * @return 
     */
    public byte getC(int i, int j){
        return get(getCIdx(i, j));
    }
    
    /**
     * Getter for transposed index
     * 转置索引的获取器
     * @param i row
     * @param j column
     * @return 
     */
    public byte getT(int idx){
        return get(getTIdx(idx));
    }
    
    /**
     * Getter for 2D coordinates, assuming first line indexing: 0 1 2 3
     * 2D坐标的获取器，假设第一行索引: 0 1 2 3
     * @param i row
     * @param j column
     * @return 
     */
    public void set(byte b, int i, int j){
        set(b, getIdx(i, j));
    }
    
    /**
     * Getter for 2D coordinates, assuming first line indexing: 0 4 8 12
     * 2D坐标的获取器，假设第一行索引:0 4 8 12
     * @param i row
     * @param j column
     * @return 
     */
    public void setC(byte b, int i, int j){
        set(b, getCIdx(i, j));
    }
    
    /**
     * Getter for transposed index
     * 转置索引的获取器
     * @param i row
     * @param j column
     * @return 
     */
    public void setT(byte b, int idx){
        set(b, getTIdx(idx));
    }
    
    /**
     * Sets column from 32bit type.
     * 设置32位类型的列。
     * Assumes we have 4 rows (32bit type).
     * 假设有4行（32位类型）。
     * @param col
     * @param idx 
     */
    public void setColumn(W32b col, int idx){
        final byte[] c = col.get();
        state[idx+ 0] = c[0];
        state[idx+ 4] = c[1];
        state[idx+ 8] = c[2];
        state[idx+12] = c[3];
    }
    
    /**
     * State initialization - memory allocation
     * 状态数组初始化 - 内存分配
     */
    public final void init(){
        if (immutable){
            throw new IllegalAccessError("State is set as immutable, cannot change");
        }
        
        state = new byte[BYTES];
    }
    
    /**
     * State initialization - memory allocation
     * 状态数组初始化 - 内存分配
     */
    public static byte[] initExt(){
        return new byte[BYTES];
    }

    /**
     * Whole state getter.
     * 整个状态数组的获取器
     * 
     * WARNING, if this object is set immutable, it should return copy of an array,
     * but from performance reasons it is not the case here.
     * 警告，如果此对象设置为不可变，则应返回数组的副本，但出于性能原因，此处不考虑这种情况
     * 
     * @return 
     */
    public byte[] getState() {
        return state;
    }
    
    /**
     * Whole state getter.
     * 整个状态数组的获取器
     * Returns copy of internal representation.
     * 返回内部表示的副本
     * 
     * @return 
     */
    public byte[] getStateCopy() {
        return Arrays.copyOf(state, BYTES);
    }

    /**
     * Whole state setter, copy
     * 整个状态数组的设置器, 拷贝
     * @param state 
     */
    public void setState(final byte[] state) {
        this.setState(state, true);
    }
    
    /**
     * State setter with optional copy.
     * 带选项的状态数组拷贝设置器
     * Copy is done via Arrays.copy, so new memory is allocated.
     * 拷贝通过Arrays.copy完成，因此分配了新内存
     * @param state
     * @param copy 
     */
    public void setState(final byte[] state, boolean copy) {
        if (state.length != BYTES) {
            throw new IllegalArgumentException("XOR table has to have 8 sub-tables");
        }
        
        if (immutable){
            throw new IllegalAccessError("State is set as immutable, cannot change");
        }
        
        if (copy){
            this.state = Arrays.copyOf(state, BYTES);
        } else {
            this.state = state;
        }
    }   
    
    /**
     * Loads state data from source to currently allocated memory.
     * 将状态数据从 源 加载到当前分配的内存
     * @param src 
     */
    public void loadFrom(final State src){
        if (immutable){
            throw new IllegalAccessError("State is set as immutable, cannot change");
        }
        
        System.arraycopy(src.getState(), 0, this.state, 0, BYTES);
    }

    /**
     * Deep copy of objects
     * 对象的深层拷贝
     * 
     * @param src
     * @param dst 
     */
    public static void copy(final State src, State dst){
        dst.setState(dst.getState(), true);
    }
    
    /**
     * Returns deep copy of state.
     * 返回对象的深层拷贝
     * 
     * @return 
     */
    public Copyable copy() {
        return new State(this.getState(), true);
    }

    public boolean isImmutable() {
        return immutable;
    }

    public void setImmutable(boolean immutable) {
        this.immutable = immutable;
    }
    
    /**
     * Transposes this state.
     * Returns this state for fluent interface.
     * 转换此状态数组
     * 返回此状态以获得流畅交互
     */
    public State transpose(){
        byte[] tmp = new byte[BYTES];
        for(int i=0; i<BYTES; i++){
            tmp[i] = this.getT(i);
        }
        
        this.state = tmp;
        return this;
    }
    
    /**
     * Transposes this state.
     * Returns new state that is transposed copy of this state.
     * 转换此状态数组
     * 返回作为此状态的转置副本的新状态
     */
    public static State getTranspose(State s){
        byte[] tmp = new byte[BYTES];
        for(int i=0; i<BYTES; i++){
            tmp[i] = s.getT(i);
        }
        
        return new State(tmp);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 59 * hash + Arrays.hashCode(this.state);
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
        final State other = (State) obj;
        if (!Arrays.equals(this.state, other.state)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        if (state==null){
            return "State{state=null}";
        }
        
        StringBuilder sb = new StringBuilder();
        final int ln = state.length;
        for(int i=0; i<ln; i++){
            sb.append(String.format("0x%02X", state[i] & 0xff));
            if ((i+1)!=ln){
                sb.append(", ");
            }
        }
        
        return "State{" + "state=" + sb.toString() + ";mem="+state+"}";
    }
}
