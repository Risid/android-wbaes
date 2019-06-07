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

import com.risid.wbaes.Utils;

import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;
import org.bouncycastle.pqc.math.linearalgebra.LittleEndianConversions;

/**
 *
 * @author ph4r05
 */
public class NTLUtils {
    // 矩阵数据真正以编码形式开始
    public static final int ENCODED_OFFSET=8; // where matrix data really start in encoded form
    
    /**
     * Generates encoded form for GF2Matrix of given size.
     * 为给定大小的GF2Matrix生成编码形式。
     * @param rows
     * @param cols
     * @return 
     */
    public static byte[] generateGF2MatrixEncodedForm(int rows, int cols){
        // Need to generate encoded form.
        // 需要生成编码形式
        final int rowBytes = Utils.ceil(cols / 8.0);
        final int size     = rowBytes * rows;
        byte[] encForm      = new byte[ENCODED_OFFSET + size];
        LittleEndianConversions.I2OSP(rows, encForm, 0);
        LittleEndianConversions.I2OSP(cols, encForm, 4);
        
        return encForm;
    }
    
    /**
     * Generates zero GF2 matrix with <rows> rows and <cols> columns.
     * 使用<rows>行和<cols>列生成空的GF2矩阵
     * @param rows
     * @param cols
     * @return 
     */
    public static GF2Matrix generateGF2Matrix(int rows, int cols){
        return new GF2Matrix(generateGF2MatrixEncodedForm(rows, cols));
    }
    
    /**
     * Generates zero GF2 matrix with <rows> rows and <cols> columns.
     * 使用<rows>行和<cols>列生成空的GF2矩阵
     * @param rows
     * @param cols
     * @return 
     */
    public static GF2Matrix generateGF2Matrix(long rows, long cols){
        return new GF2Matrix(generateGF2MatrixEncodedForm((int)rows, (int)cols));
    }
    
    /**
     * Takes 8bit number (BYTE / unsigned char) and stores its bit representation to col vector
     * starting at given coordinates to array (may be mat_GF2). LSB first.
     * 取8位数（BYTE / unsigned char）并将其位表示存储到col矢量，从给定坐标开始到数组（可能是mat_GF2）。
     *
     * 最低位优先优先。
     * 
     * @param m
     * @param src
     * @param i     row
     * @param j     column
     */
    public static void putByteAsColVector(GF2MatrixEx m, byte c, int i, int j){
        for(int k=0; k<8; k++){
            m.set(i+k, j, c & (1<<k));
        }
    }
    
    
    /**
     * Takes 8bit number (BYTE / unsigned char) and stores its bit representation to row vector
     * starting at given coordinates to array (may be mat_GF2). MSB first - natural representation.
     * 取8位数（BYTE / unsigned char）并将其位表示存储到从给定坐标开始到行数的行向量（可以是mat_GF2）。
     * 自然表示 - 最高位优先
     * @param m
     * @param src
     * @param i     row
     * @param j     column
     */
    public static void putByteAsRowVector(GF2MatrixEx m, byte c, int i, int j){
        for(int k=0; k<8; k++){
            m.set(i, j+k, c & (1<<(7-k)));
        }
    }
    
    /**
     * Assembles 8bit number (BYTE / unsigned char) from bit representation in column vector. LSB first.
     * 从列向量中的位表示8位数（BYTE / unsigned char）
     * 最低位优先优先
     * @param src
     * @param i     row
     * @param j     column
     * @return 
     */
    public static byte colBinaryVectorToByte(final GF2MatrixEx src, int i, int j){
        long res = 0;
        for(int k=0; k<8; k++){
            res |= src.get(i+k, j)==0 ? 0 : 1<<k;
        }
        
        return (byte)res;
    }
    
    /**
     * Assembles 8bit number (BYTE / unsigned char) from bit representation in column vector. LSB first.
     * 从列向量中的位表示8位数（BYTE / unsigned char）
     *
     * 最低位优先优先
     * @param src
     * @param i     row
     * @param j     column
     * @return 
     */
    public static byte rowBinaryVectorToByte(final GF2MatrixEx src, int i, int j){
        byte res = 0;
        for(int k=0; k<8; k++){
            res |= src.get(i, j+k)==0 ? 0 : 1<<k;
        }
        
        return res;
    }
    
    /**
     * Sets whole matrix to zero
     * 置零
     * 
     * @param m
     * @return 
     */
    public static void zero(GF2MatrixEx m){
        if (m.getNumRows()==0 || m.getNumColumns()==0) {
            return;
        }
        
        int[][] mi  = m.getIntArray();        
        final int k = mi[0].length;
        for(int i=0; i<mi.length; i++){
            for(int j=0; j<mi[i].length; j++){
                mi[i][j] = 0;
            }
        }
    }
    
    public static String chex(int n) {
        // call toUpperCase() if that's required
        // 如果需要，调用 toUpperCase()
        return String.format("0x%02X", n);
    }
    
    /**
     * Returns true if the matrix has unit form (i.e., ones on main diagonal,
     * zeros elsewhere).
     * 如果矩阵具有单位形式（即主对角线上的那些，其他地方为零），则返回true。
     * 
     * @param m
     * @return 
     */
    public static boolean isUnit(GF2MatrixEx m){
        final int rows = m.getNumRows();
        final int cols = m.getNumColumns();
        if (rows!=cols){
            return false;
        }
        
        return isNormalizedRank(m, rows);
    }
    
    /**
     * Returns true if matrix has normalized form of given rank
     * 如果矩阵具有给定等级的规范化形式，则返回true
     * @param m
     * @param rank
     * @return
     */
    public static boolean isNormalizedRank(GF2MatrixEx m, int rank){
        // test resulting normal matrix for correct form
        // 测试得到正常矩阵的正确形式
        final int rows = m.getNumRows();
        final int cols = m.getNumColumns();
        
        boolean matrixOK=true;
        for(int i=0; i<rows; i++){
            for(int j=0; j<cols; j++){
                // test on zero outside of main diagonal
                // 在主对角线外的零点上测试
                if (i!=j && m.isSet(i, j)) {
                    matrixOK=false;
                    break;
                }

                // test on ones on main diagonal
                // 测试主对角线上的
                if (i==j){
                    // test for one on main diagonal for rank
                    // 主对角线的元素以测试矩阵秩
                    if (i<rank && !m.isSet(i, j)){
                        matrixOK=false;
                        break;
                    }

                    // test for zero on main diagonal
                    // 测试零元素在主对角线上
                    if (i>=rank && m.isSet(i, j)){
                        matrixOK=false;
                        break;
                    }
                }
            }
        }
        
        return matrixOK;
    }
    
    
    /**
     * Converts matrix consisting of GF2E elements to binary matrix from element
     * representation, coding binary elements to columns. LSB is first in the
     * row, what is consistent with GenericAES.
     *
     * 将包含GF2E元素的矩阵从元素表示转换为二进制矩阵，将二进制元素编码为列
     * 最低位优先，与GenericAES一致。
     */
    public static GF2MatrixEx GF2mMatrix_to_GF2Matrix_col(final GF2mMatrixEx src, int elemLen) {
        int i, j, k, n = src.getNumRows(), m = src.getNumColumns();

        GF2MatrixEx dst = new GF2MatrixEx(elemLen * n, m);
        for (i = 0; i < n; i++) {
            for (j = 0; j < m; j++) {
                int curElem = src.get(i, j);
                for (k = 0; k < elemLen; k++) {
                    dst.set(i * elemLen + k, j, (curElem >>> k) & 0x1); //k <= xdeg ? curX[k] : 0);
                }
            }
        }

        return dst;
    }
    
    /**
     * Converts column of 32 binary values to W32b value
     * 将32个二进制值的列转换为W32b值
     * @param src
     * @param row
     * @param col
     * @return 
     */
    public static long GF2Matrix_to_long(final GF2MatrixEx src, int row, int col){
        //assert((src.NumRows()) < (row*8));
        //assert((src.NumCols()) < col);
        long dst = 0;
        dst |= Utils.byte2long(colBinaryVectorToByte(src, row+8*0, col), 0);
        dst |= Utils.byte2long(colBinaryVectorToByte(src, row+8*1, col), 1);
        dst |= Utils.byte2long(colBinaryVectorToByte(src, row+8*2, col), 2);
        dst |= Utils.byte2long(colBinaryVectorToByte(src, row+8*3, col), 3);
        return dst;
    }

}
