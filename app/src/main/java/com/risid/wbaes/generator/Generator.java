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
import com.risid.wbaes.T1Box;
import com.risid.wbaes.T2Box;
import com.risid.wbaes.T3Box;
import com.risid.wbaes.Utils;
import com.risid.wbaes.XORCascade;
import com.risid.wbaes.XORCascadeState;

import org.bouncycastle.pqc.math.linearalgebra.GF2mField;

import java.security.SecureRandom;

/**
 * Class generates whitebox AES table representation.
 * 该类为白盒AES表生成器
 *
 * AES: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 * @author ph4r05
 */
public class Generator {
    // CODING CONSTANTS
    // 白盒编码常量
    public static final int  NO_CODING          = 0x00000000;  // IDENTITY CODING
    public static final int  UNASSIGNED_CODING  = 0xFFFFFFFF;  // INVALID CODING
    public static final int  UNUSED_CODING      = 0xFFFFFFFE;  // This coding is not in use (XOR tables use only lower 4 bits for result)
    public static boolean    USE_IDENTITY_CODING(int idx){
        return ((idx) == NO_CODING || (idx) == UNASSIGNED_CODING || (idx) == UNUSED_CODING);
    }
    // VALID CODINGS ORDINARY NUMBER IS FROM 0x00000000 TO 0xFFFFFFFE (TOTAL COUNT == 2^32 - 1) 
    //合法的编码二进制范围应该是从0x00000000 到 0xFFFFFFFE ，一共 2^32 - 1个
    // CODING SIZE TYPE
    // 编码大小类型
    public static final int  COD_BITS_UNASSIGNED = 0x00;
    public static final int  COD_BITS_4          = 0x01;
    public static final int  COD_BITS_8          = 0x02;
    public static final int  COD_BITS_8_EXT      = 0x04;
    public static final int  COD_BITS_EXT        = 0x20;

    // MIXING BIJECTION TYPE
    // 混合双射类型
    public static final int  MB_IDENTITY = 0x00;
    public static final int  MB_8x8      = 0x01;
    public static final int  MB_32x32    = 0x02;
    public static final int  MB_128x128  = 0x04;

    // MIXING BIJECTION COUNTS
    // 混合双射计数器
    public static final int  MB_CNT_08x08_ROUNDS    = 9;
    public static final int  MB_CNT_08x08_PER_ROUND = 16;
    public static final int  MB_CNT_32x32_ROUNDS    = 9;
    public static final int  MB_CNT_32x32_PER_ROUND = 4;

    // NUMBER OF XOR TABLES FOR ONE T1 TABLE
    // 每轮T1表的XOR表个数
    public static final int  XTB_CNT_T1 = 480;

    // EXTERNAL ENCODINGS
    // 扩展编码
    public static final int WBAESGEN_EXTGEN_fCID=1;          // lfC[0]  in ExtEncoding will be identity
    public static final int WBAESGEN_EXTGEN_lCID=2;          // lfC[1]  in ExtEncoding will be identity
    public static final int WBAESGEN_EXTGEN_IDMID=4;         // IODM[0] in ExtEncoding will be identity
    public static final int WBAESGEN_EXTGEN_ODMID=8;         // IODM[1] in ExtEncoding will be identity

    // whole ExtEncoding will be identity
    // 整个扩展编码定义
    public static final int WBAESGEN_EXTGEN_ID = (WBAESGEN_EXTGEN_fCID | WBAESGEN_EXTGEN_lCID | WBAESGEN_EXTGEN_IDMID | WBAESGEN_EXTGEN_ODMID);

    public static int nextTbox(int idx, boolean encrypt){
        return AES.shift(idx, !encrypt);
    }

    //
    //  HIGHLOW, DEFINE TWO 4-BITS CODING FOR 8-BITS ARGUMENT
    // 高低位，为8bit的参数定义2个4bit的编码
    //
    public static class HighLow {
        public byte type = COD_BITS_UNASSIGNED;   // CODING SIZE TYPE. CURRENTLY DEFINED COD_BITS_4 & COD_BITS_8   
        public int H = NO_CODING;       // HIGH 4-BITS CODING (H == L for COD_BITS_8)
        public int L = NO_CODING;       // LOW 4-BITS CODING

        @Override
        public String toString() {
            return "HL{H=" + H + ", L=" + L + '}';
        }
    }

    //
    //  CODING, DEFINE INPUT AND OUTPUT WBACR AES CODING FOR 8-BITS ARGUMENT
    // 为8位参数编码、定义输入和输出WBACR AES编码
    //
    public static class Coding {
        public HighLow IC;
        public HighLow OC;

        public Coding() {
            IC = new HighLow();
            OC = new HighLow();
        }

        @Override
        public String toString() {
            return "Coding{" + "IC=" + IC + ", OC=" + OC + '}';
        }
    }

    //
    //  4-BITS TO 4-BITS BIJECTION
    // 4bit转4bit双射
    //
    public static class Coding4x4Table{
        public Bijection4x4   coding;
        // 效率优化，可以从编码元素（由于双射属性）中计算出来。
        public Bijection4x4   invCoding;          // SPEED OPTIMALIZATION, CAN BE ALSO COMPUTED FROM coding MEMBER (DUE TO BIJECTION PROPERTY)

        public Coding4x4Table() {
            coding    = new Bijection4x4();
            invCoding = new Bijection4x4();
        }
    }

    //
    //  8-BITS TO 8-BITS BIJECTION
    // 8bit转8bit双射
    //
    public static class Coding8x8Table{
        public Bijection8x8   coding;
        public Bijection8x8   invCoding;          // SPEED OPTIMALIZATION, CAN BE ALSO COMPUTED FROM coding MEMBER (DUE TO BIJECTION PROPERTY)

        public Coding8x8Table() {
            coding    = new Bijection8x8();
            invCoding = new Bijection8x8();
        }
    }

    public static class XORCODING {
        public Coding xtb[];
        public final int width;

        public XORCODING(Coding[] xtb) {
            this.xtb = xtb;
            this.width = xtb.length;
        }

        public XORCODING(int width) {
            this.width = width;
            this.xtb   = new Coding[width];
            for(int i=0; i<width; i++){
                this.xtb[i] = new Coding();
            }
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            for(int i=0; xtb!=null  && i<width && xtb[i]!=null; i++){
                sb.append(i).append(':').append(xtb[i]).append(";\n");
            }
            return "XORCODING{width=" + width + "; xtb=\n"+sb.toString()+"}";
        }
    }

    //
    // Generic coding for 8bit input argument coding
    // 8位输入参数编码的通用编码
    //
    public static class W08xZZCODING {
        public HighLow   IC;
        public HighLow   OC[];          // SPEED OPTIMALIZATION, CAN BE ALSO COMPUTED FROM coding MEMBER (DUE TO BIJECTION PROPERTY)
        public final int width;

        public W08xZZCODING(HighLow IC, HighLow[] OC) {
            this.IC = IC;
            this.OC = OC;
            this.width = OC.length;
        }

        public W08xZZCODING(int width) {
            this.width = width;
            IC = new HighLow();
            OC = new HighLow[width];
            for(int i=0; i<width; i++){
                OC[i] = new HighLow();
            }
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            for(int i=0; OC!=null  && i<width && OC[i]!=null; i++){
                sb.append(i).append(':').append(OC[i]).append(";\n");
            }
            return "W08xZZCODING{width=" + width + "; IC=" + IC
                    + "; OC=\n" + sb.toString() + ";}";
        }
    }

    //
    // Coding for T2 and T3 boxes, 8bit -> 32bit
    // T2和T3盒编码，8bit -> 32bit
    //
    public static class W08x32Coding extends W08xZZCODING{
        public W08x32Coding() {
            super(4);
        }
    }

    //
    // Coding for T1 boxes, 8bit -> 128bit
    // T1盒编码，8bit -> 128bit
    //
    public static class W08x128Coding extends W08xZZCODING{
        public W08x128Coding() {
            super(16);
        }
    }

    public static void assrt(boolean condition){
        if (!condition){
            assert(condition);
            throw new AssertionError("Condition wasn't met");
        }
    }

    // Positive modulo
    // 正模
    public static int posMod(int a, int m){
        return (((a) % (m)) < 0 ? ((a) % (m)) + (m) : (a) % (m));
    }

    public static int posIdx(byte x){
        return x & 0xff;
    }

    public static int posIdx(int x){
        return x & 0xffffffff;
    }

    /**
     * HI(xxxxyyyy) = 0000xxxx
     * 取高位
     * @param x
     * @return
     */
    public static byte HI(byte x){
        return (byte) (((x) >>> 4) & 0xF);
    }

    /**
     * LO(xxxxyyyy) = 0000yyyy
     * 取低位
     * @param x
     * @return
     */
    public static byte LO(byte x){
        return (byte) ((x) & 0xF);
    }

    /**
     * HILO(qqqqwwww, rrrrtttt) = wwwwtttt
     * @param h
     * @param l
     * @return
     */
    public static byte HILO(byte h, byte l){
        return (byte) ((((h) & 0xF) << 4) | (l & 0xF));
    }

    //
    // Allocates new 4X4 encodings for 08xZZ tables (T1,T2,T3) from given offset (can be used to allocate also T1)
    // Allocation = generate unique bijection ID for particular IO box.
    // Only OC (output coding) is generated = donor of the bijection. IC = acceptor and is set by CONNECT* macros
    // From other tables OC fields.
    // 从给定的偏移量为08xzz表（T1、T2、T3）分配新的4x4编码（也可用于分配T1）
    // 分配 = 为特定IO盒生成唯一的双射ID
    // 仅生成输出编码 = 双射的提供。 输入编码来自接受器并由CONNECT *宏设置
    // 来自其它表的输出域

    public static int ALLOCW08xZZCodingEx(W08xZZCODING cod, int ofs, int idx) {
        for(int i=0; i<cod.width; i++){
            cod.OC[(ofs)+i].type = COD_BITS_4;

            // To avoid overwriting already allocated encodings.
            // 避免覆盖已分配的编码
            assrt(cod.OC[(ofs)+i].H==NO_CODING);
            assrt(cod.OC[(ofs)+i].L==NO_CODING);

            cod.OC[(ofs)+i].L = ++(idx);
            cod.OC[(ofs)+i].H = ++(idx);
        }

        return idx;
    }

    //
    // Allocates new 4X4 encodings for 08x32 tables (T2,T3) from given offset (can be used to allocate also T1)
    // Allocation = generate unique bijection ID for particular IO box.
    // Only OC (output coding) is generated = donor of the bijection. IC = acceptor and is set by CONNECT* macros
    // From other tables OC fields.
    //
    // 从给定的偏移量为08x32表（T2、T3）分配新的4x4编码（也可用于分配T1）
    // 分配 = 为特定IO盒生成唯一的双射ID
    // 仅生成输出编码 = 双射的提供。 输入编码来自接受器并由CONNECT *宏设置
    // 来自其它表的输出域
    public static int ALLOCW08x32CodingEx(W08x32Coding cod, int ofs, int idx) {
        return ALLOCW08xZZCodingEx(cod, ofs, idx);
    }

    public static int ALLOCW08x32CodingEx(W08x32Coding cod, int idx) {
        return ALLOCW08x32CodingEx(cod, 0, idx);
    }

    //
    // Allocate T1 tables - generate bijection IDs for output side of the table (128-bit wide)
    // 分配T1表 - 为表的输出端生成双射ID（128bit大小）
    //
    public static int ALLOCW08x128Coding(W08x128Coding cod, int idx) {
        return ALLOCW08xZZCodingEx(cod, 0, idx);
    }

    //
    // Allocates new output coding for 4-bit XOR boxes XTB[offset+0 - offset+7], altogether 32 bit XOR table
    // 为4位XOR盒分配新的输出编码XTB [offset + 0  -  offset + 7]，共32位XOR表
    // Recall that output of XOR is stored in LOW part, thus upper is unused -> no allocation for upper part.
    // 回想一下，XOR的输出存储在低位，因此高位是未使用的，即没有为高位分配
    //
    public static int ALLOCXORCoding(XORCODING xtb, int offset, int idx, int len) {
        for(int i=0; i<len; i++){
            // To avoid overwriting already allocated encodings.
            // 避免覆盖已分配的编码
            assrt(xtb.xtb[(offset)+i].OC.L==NO_CODING);

            xtb.xtb[(offset)+i].OC.type = COD_BITS_4;
            xtb.xtb[(offset)+i].OC.H    = UNUSED_CODING;
            xtb.xtb[(offset)+i].OC.L    = ++(idx);
        }

        return idx;
    }


    //
    // Connects OUTPUT coding of 32bit wide boxes (T2,T3) to INPUT coding of XOR boxes, 32bit wide. 
    // Each XOR box accepts 2 arguments, first in HIGH part, second in LOW part, thus when associating
    // mapping from one particular W32box we are using either HIGH or LOW parts.
    // 将32位宽盒（T2，T3）的输出编码连接到32位宽的XOR盒的输入编码
    // 每个XOR盒接受2个参数，先是HIGH部分，第二个是LOW部分，
    // 因此当连接来自一个特定W32box的映射时，我们使用HIGH或LOW部分。
    //
    public static void CONNECT_W08x32_TO_XOR_EX(W08xZZCODING cod, XORCODING xtb, boolean HL, int offsetL, int offsetR) {
        // Connects 32 bit output to XOR encoding with 4bit width, thus 8 connections are needed.
        // 将32位输出连接到4位宽度的XOR编码，因此需要8个连接
        for (int i=0; i<4; i++){
            // To avoid overwriting already allocated encodings.
            // 防已分配
            assrt(HL ? xtb.xtb[(offsetL)+2*i  ].IC.H==NO_CODING : xtb.xtb[(offsetL)+2*i  ].IC.L==NO_CODING);
            assrt(HL ? xtb.xtb[(offsetL)+2*i+1].IC.H==NO_CODING : xtb.xtb[(offsetL)+2*i+1].IC.L==NO_CODING);
            // To avoid assigning empty/invalid encoding.
            // 防止非法或空的编码
            assrt(cod.OC[(offsetR)+i].H!=NO_CODING && cod.OC[(offsetR)+i].H!=UNASSIGNED_CODING);
            assrt(cod.OC[(offsetR)+i].L!=NO_CODING && cod.OC[(offsetR)+i].L!=UNASSIGNED_CODING);

            xtb.xtb[(offsetL)+2*i  ].IC.type = COD_BITS_4;
            xtb.xtb[(offsetL)+2*i+1].IC.type = COD_BITS_4;
            if (HL){
                xtb.xtb[(offsetL)+2*i  ].IC.H = cod.OC[(offsetR)+i].L;
                xtb.xtb[(offsetL)+2*i+1].IC.H = cod.OC[(offsetR)+i].H;
            } else {
                xtb.xtb[(offsetL)+2*i  ].IC.L = cod.OC[(offsetR)+i].L;
                xtb.xtb[(offsetL)+2*i+1].IC.L = cod.OC[(offsetR)+i].H;
            }
        }
    }

    public static void CONNECT_W08x32_TO_XOR_H_EX(W08xZZCODING cod, XORCODING xtb, int offsetL, int offsetR){
        CONNECT_W08x32_TO_XOR_EX(cod, xtb, true, offsetL, offsetR);
    }

    public static void CONNECT_W08x32_TO_XOR_L_EX(W08xZZCODING cod, XORCODING xtb, int offsetL, int offsetR){
        CONNECT_W08x32_TO_XOR_EX(cod, xtb, false, offsetL, offsetR);
    }

    public static void CONNECT_W08x32_TO_XOR(W08xZZCODING cod, XORCODING xtb, boolean HL, int offset) {
        CONNECT_W08x32_TO_XOR_EX(cod, xtb, HL, offset, 0);
    }

    public static void CONNECT_W08x32_TO_XOR_H(W08xZZCODING cod, XORCODING xtb, int offset) {
        CONNECT_W08x32_TO_XOR_H_EX(cod, xtb, offset, 0);
    }

    public static void CONNECT_W08x32_TO_XOR_L(W08xZZCODING cod, XORCODING xtb, int offset) {
        CONNECT_W08x32_TO_XOR_L_EX(cod, xtb, offset, 0);
    }

    //
    // Connects OUTPUT coding for XOR tables to INPUT coding of XOR tables on lower layer.
    // Has effect of combining result of 2XOR tables to input of 1 XOR table.
    //
    // Recall that XOR result is always stored in lower part of XOR, thus on the left side we
    // are using OC.L;
    //
    // 1 XOR table accepts input from 2 sources. 
    // In HIGH part is first argument, in LOW part is the second. Same functionality as
    // in CONNECT_W08x32_TO_XOR macro
    //
    // This macro accepts XOR tables 32bit wide.
    // 将XOR表的OUTPUT编码连接到下层的XOR表的INPUT编码。
    // 会影响2XOR表与1XOR表的输入组合的结果
    // 由于XOR结果始终存储在XOR的低位，因此在左侧我们使用输出编码的低位
    //
    // 1个XOR表接受来自2个源的输入
    // 第一个参数为高位，第二个是低位。与CONNECT_W08x32_TO_XOR宏功能相同
    // 该宏接受32位宽的XOR表
    //
    //
    public static void CONNECT_XOR_TO_XOR(XORCODING xtb1, int offset1, XORCODING xtb3, int offset3, boolean HL) {
        for (int i = 0; i < 8; i++) {
            // To avoid overwriting already connected encoding.
            // 防重写已连接的编码
            assrt(HL ? xtb3.xtb[(offset3) + i].IC.H == NO_CODING : xtb3.xtb[(offset3) + i].IC.L == NO_CODING);
            // To avoid assigning empty encodings.
            // 防止分配空编码
            assrt(xtb1.xtb[(offset1) + i].OC.L != NO_CODING && xtb1.xtb[(offset1) + i].OC.L != UNASSIGNED_CODING);

            xtb3.xtb[(offset3) + i].IC.type = COD_BITS_4;
            if (HL) {
                xtb3.xtb[(offset3) + i].IC.H = xtb1.xtb[(offset1) + i].OC.L;
            } else {
                xtb3.xtb[(offset3) + i].IC.L = xtb1.xtb[(offset1) + i].OC.L;
            }
        }
    }

    public static void CONNECT_XOR_TO_XOR_128(XORCODING xtb1, int offset1, XORCODING xtb3, int offset3, boolean HL) {
        CONNECT_XOR_TO_XOR(xtb1, (offset1)+0,  xtb3, (offset3)+0,  HL);
        CONNECT_XOR_TO_XOR(xtb1, (offset1)+8,  xtb3, (offset3)+8,  HL);
        CONNECT_XOR_TO_XOR(xtb1, (offset1)+16, xtb3, (offset3)+16, HL);
        CONNECT_XOR_TO_XOR(xtb1, (offset1)+24, xtb3, (offset3)+24, HL);
    }

    public static void CONNECT_XOR_TO_XOR_H(XORCODING xtb1, int offset1, XORCODING xtb3, int offset3) {
        CONNECT_XOR_TO_XOR(xtb1, offset1, xtb3, offset3, true);
    }

    public static void CONNECT_XOR_TO_XOR_L(XORCODING xtb1, int offset1, XORCODING xtb3, int offset3){
        CONNECT_XOR_TO_XOR(xtb1, offset1, xtb3, offset3, false);
    }

    public static void CONNECT_XOR_TO_XOR_128_H(XORCODING xtb1, int offset1, XORCODING xtb3, int offset3){
        CONNECT_XOR_TO_XOR_128(xtb1, offset1, xtb3, offset3, true);
    }

    public static void CONNECT_XOR_TO_XOR_128_L(XORCODING xtb1, int offset1, XORCODING xtb3, int offset3){
        CONNECT_XOR_TO_XOR_128(xtb1, offset1, xtb3, offset3, false);
    }

    //
    // Connects 8bit output from 2 consecutive XOR tables to 8b input of W08xZZ table
    // 将2个连续XOR表的8bit输出连接到W08xZZ表的8bit输入
    //
    public static void CONNECT_XOR_TO_W08x32(XORCODING xtb, int offset, W08xZZCODING cod) {
        cod.IC.type = xtb.xtb[(offset)+0].OC.type;

        // Asserts checks if someone is not trying to overwrite already allocated
        // mappings on inputs (INPUT). If there is already some coding, no
        // re-assign is allowed.
        // It is also checked if output mapping has some meaningful coding
        // if somebody is trying to assing it somewhere.
        // 断言检查是否尝试覆盖输入上已分配的映射。
        // 如果已经有一些编码，则不允许重新分配。
        // 如果试图在某处进行分配，则检查输出映射是否已有某些有意义的编码
        assrt(cod.IC.H==NO_CODING);
        assrt(xtb.xtb[(offset)+0].OC.L!=UNASSIGNED_CODING && xtb.xtb[(offset)+0].OC.L!=NO_CODING);
        assrt(cod.IC.L==NO_CODING);
        assrt(xtb.xtb[(offset)+1].OC.L!=UNASSIGNED_CODING && xtb.xtb[(offset)+1].OC.L!=NO_CODING);

        cod.IC.type = COD_BITS_4;
        cod.IC.L = xtb.xtb[(offset)+0].OC.L;
        cod.IC.H = xtb.xtb[(offset)+1].OC.L;
    }

    /**
     * Encodes with IO bijection src byte according to hl scheme.
     * 根据hl方案使用IO双射src字节进行编码
     * @param src
     * @param hl
     * @param inverse
     * @param tbl4
     * @param tbl8
     * @return
     */
    public static byte iocoding_encode08x08(byte src, HighLow hl, boolean inverse, Bijection4x4[] tbl4, Bijection8x8[] tbl8){
        if (hl.type == COD_BITS_4){
            if(tbl4==null
                    || (hl.H >= 0 && (tbl4.length <= hl.H || tbl4[hl.H]==null))
                    || (hl.L >= 0 && (tbl4.length <= hl.L || tbl4[hl.L]==null))){
                throw new NullPointerException("Illegal allocation");
            }

            return inverse ?
                    HILO(
                            USE_IDENTITY_CODING(hl.H) ? HI(src) : tbl4[hl.H].invCoding[HI(src)],
                            USE_IDENTITY_CODING(hl.L) ? LO(src) : tbl4[hl.L].invCoding[LO(src)])

                    : HILO(
                    USE_IDENTITY_CODING(hl.H) ? HI(src) : tbl4[hl.H].coding[HI(src)],
                    USE_IDENTITY_CODING(hl.L) ? LO(src) : tbl4[hl.L].coding[LO(src)]);
        } else if (hl.type == COD_BITS_8){
            assrt(tbl8 != null);
            return inverse ?
                    (USE_IDENTITY_CODING(hl.L) ? src : tbl8[hl.L].invCoding[src])
                    : (USE_IDENTITY_CODING(hl.L) ? src : tbl8[hl.L].coding[src]);
        }

        return src;
    }

    /**
     * Encodes with IO bijection src byte according to Coding scheme.
     * 根据编码方案使用IO双射src字节进行编码
     * @param src
     * @param coding
     * @param encodeInput
     * @param tbl4
     * @param tbl8
     * @return
     */
    public static byte iocoding_encode08x08(byte src, Coding coding, boolean encodeInput, Bijection4x4[] tbl4, Bijection8x8[] tbl8){
        HighLow hl = encodeInput ? coding.IC : coding.OC;
        return iocoding_encode08x08(src, hl, encodeInput, tbl4, tbl8);
    }

    /**
     * Encodes with IO bijection src 32bit argument according to Coding scheme.
     * 根据编码方案使用IO 双射对 src 的 32bit参数进行编码
     * @param src
     * @param coding
     * @param encodeInput
     * @param tbl4
     * @param tbl8
     * @return
     */
    public static long iocoding_encode32x32(long src, W08x32Coding coding, boolean encodeInput, Bijection4x4[] tbl4, Bijection8x8[] tbl8){
        // encoding input - special case, input is just 8bit wide
        // 编码输入 - 特殊情况，输入只有8位
        long dst = 0;
        if (encodeInput){
            dst |= Utils.byte2long(iocoding_encode08x08(Utils.long2byte(src, 0), coding.IC, encodeInput, tbl4, tbl8), 0);
            dst |= Utils.byte2long(iocoding_encode08x08(Utils.long2byte(src, 1), coding.IC, encodeInput, tbl4, tbl8), 1);
            dst |= Utils.byte2long(iocoding_encode08x08(Utils.long2byte(src, 2), coding.IC, encodeInput, tbl4, tbl8), 2);
            dst |= Utils.byte2long(iocoding_encode08x08(Utils.long2byte(src, 3), coding.IC, encodeInput, tbl4, tbl8), 3);
        } else {
            dst |= Utils.byte2long(iocoding_encode08x08(Utils.long2byte(src, 0), coding.OC[0], encodeInput, tbl4, tbl8), 0);
            dst |= Utils.byte2long(iocoding_encode08x08(Utils.long2byte(src, 1), coding.OC[1], encodeInput, tbl4, tbl8), 1);
            dst |= Utils.byte2long(iocoding_encode08x08(Utils.long2byte(src, 2), coding.OC[2], encodeInput, tbl4, tbl8), 2);
            dst |= Utils.byte2long(iocoding_encode08x08(Utils.long2byte(src, 3), coding.OC[3], encodeInput, tbl4, tbl8), 3);
        }
        return dst;
    }

    /**
     * Encodes with IO bijection src 128bit argument according to Coding scheme.
     * 根据编码方案对IO双射的src 128bit的参数编码
     * @param dst
     * @param src
     * @param coding
     * @param encodeInput
     * @param tbl4
     * @param tbl8
     */
    public static void iocoding_encode128x128(State dst, State src, W08x128Coding coding, boolean encodeInput, Bijection4x4[] tbl4, Bijection8x8[] tbl8) {
        // encoding input - special case, input is just 8bit wide
        // 编码输入 - 特殊情况，输入只有8位
        if (encodeInput) {
            for (int i = 0; i < State.BYTES; i++) {
                dst.set(iocoding_encode08x08(src.get(i), coding.IC, encodeInput, tbl4, tbl8), i);
            }
        } else {
            for (int i = 0; i < State.BYTES; i++) {
                dst.set(iocoding_encode08x08(src.get(i), coding.OC[i], encodeInput, tbl4, tbl8), i);
            }
        }
    }

    private AEShelper AESh;
    private AES AESi;
    private AESCodingMap AESMap;
    private InternalBijections io;
    private ExternalBijections extc;
    private boolean debug = false;
    private SecureRandom rand = new SecureRandom();

    private boolean useIO04x04Identity=false;
    private boolean useIO08x08Identity=true;
    private boolean useMB08x08Identity=false;
    private boolean useMB32x32Identity=false;

    /**
     * Generates mixing bijections (linear transformations) for AES algorithm.
     * 为AES算法生成混合双射（线性变换）
     * @param io
     * @param L08x08rounds
     * @param MB32x32rounds
     * @param MB08x08Identity
     * @param MB32x32Identity
     * @return
     */
    public int generateMixingBijections(InternalBijections io,
                                        int L08x08rounds, int MB32x32rounds,
                                        boolean MB08x08Identity, boolean MB32x32Identity){

        int r,i;
        LinearBijection[][] L08x08  = io.getMB_L08x08();
        LinearBijection[][] MB32x32 = io.getMB_MB32x32();

        // Generate all required 8x8 mixing bijections.
        //生成所有必需的8x8混合双射。
        for (r = 0; r < L08x08rounds; r++) {
            for (i = 0; i < MB_CNT_08x08_PER_ROUND; i++) {
                if (!MB08x08Identity) {
                    final GF2MatrixEx m    = MixingBijection.generateMixingBijection(8, 4, rand, debug);
                    final GF2MatrixEx minv = (GF2MatrixEx) m.computeInverse();

                    L08x08[r][i].setMb(m);
                    L08x08[r][i].setInv(minv);
                } else {
                    L08x08[r][i].setMb( new GF2MatrixEx(8, GF2MatrixEx.MATRIX_TYPE_UNIT));
                    L08x08[r][i].setInv(new GF2MatrixEx(8, GF2MatrixEx.MATRIX_TYPE_UNIT));
                }
            }
        }

        // Generate all required 32x32 mixing bijections.
        // 生成所有必需的32x32混合双射
        for (r = 0; r < MB32x32rounds; r++) {
            for (i = 0; i < MB_CNT_32x32_PER_ROUND; i++) {
                if (!MB32x32Identity) {
                    final GF2MatrixEx m    = MixingBijection.generateMixingBijection(32, 4, rand, debug);
                    final GF2MatrixEx minv = (GF2MatrixEx) m.computeInverse();

                    MB32x32[r][i].setMb(m);
                    MB32x32[r][i].setInv(minv);
                } else {
                    MB32x32[r][i].setMb( new GF2MatrixEx(32, GF2MatrixEx.MATRIX_TYPE_UNIT));
                    MB32x32[r][i].setInv(new GF2MatrixEx(32, GF2MatrixEx.MATRIX_TYPE_UNIT));
                }
            }
        }
        return 0;
    }

    /**
     * Generate mixing bijections for AES, for current instance.
     * 为当前实例生成AES的混合双射
     * @param identity
     * @return
     */
    public int generateMixingBijections(boolean identity){
        return generateMixingBijections(io, MB_CNT_08x08_ROUNDS, MB_CNT_32x32_ROUNDS, identity, identity);
    }

    public int generate4X4Bijections(Bijection4x4[] tbl, int size, boolean identity){
        int i=0,c=0;
        for(; i<size; i++){
            // HINT: if you are debugging IO problems, try to turn on and off some bijections,
            // you can very easily localize the problem.
            // 提示：如果您正在调试IO编码问题，尝试打开和关闭双射，您可以非常轻松地将问题解决

            //if (i>=2988) identity=true;
            c |= generate4X4Bijection(tbl[i], identity);
        }

        return c;
    }

    public int generate8X8Bijections(Bijection8x8[] tbl, int size, boolean identity){
        int i=0,c=0;
        for(; i<size; i++){
            c |= generate8X8Bijection(tbl[i], identity);
        }

        return c;
    }

    public int generate4X4Bijection(Bijection4x4 tbl, boolean identity) {
        if (!identity) {
            return GenUtils.generateRandomBijection(tbl.coding, tbl.invCoding, 16, true, rand);
        } else {
            byte i;
            for (i = 0; i < 16; i++) {
                tbl.coding[i] = i;
                tbl.invCoding[i] = i;
            }

            return 0;
        }
    }

    public int generate8X8Bijection(Bijection8x8 tbl, boolean identity) {
        if (!identity) {
            return GenUtils.generateRandomBijection(tbl.coding, tbl.invCoding, 256, true, rand);
        } else {
            int i;
            for (i = 0; i < 256; i++) {
                tbl.coding[i] = (byte)i;
                tbl.invCoding[i] = (byte)i;
            }

            return 0;
        }
    }

    /**
     * Generates external encodings randomly.
     * 随机生成外部编码
     * @param extc
     * @param flags can determine whether some of generated bijections are identities.
     *              可以确定某些生成的双射是否是恒等式
     */
    public void generateExtEncoding(ExternalBijections extc, int flags){
        int k;

        // Initialize memory if empty
        // 初始化分配内存
        extc.memoryAllocate();

        // generate 8x8 bijections at first
        // 先生成8x8双射
        for(k=0; k<2; k++){
            boolean identity = (k==0 && (flags & WBAESGEN_EXTGEN_fCID) > 0) || (k==1 && (flags & WBAESGEN_EXTGEN_lCID) > 0);
            generate4X4Bijections(extc.getLfC()[k], 2*AES.BYTES, identity);
        }

        // generate mixing bijection
        // 生成混合双射
        for(k=0; k<2; k++){
            boolean identity = (k==0 && (flags & WBAESGEN_EXTGEN_IDMID) > 0) || (k==1 && (flags & WBAESGEN_EXTGEN_ODMID) > 0);
            if (!identity){
                final GF2MatrixEx m    = MixingBijection.generateMixingBijection(128, 4, rand, debug);
                final GF2MatrixEx minv = (GF2MatrixEx) m.computeInverse();

                extc.getIODM()[k].setMb(m);
                extc.getIODM()[k].setInv(minv);
            } else {
                extc.getIODM()[k].setMb( new GF2MatrixEx(128, GF2MatrixEx.MATRIX_TYPE_UNIT));
                extc.getIODM()[k].setInv(new GF2MatrixEx(128, GF2MatrixEx.MATRIX_TYPE_UNIT));
            }
        }
    }

    /**
     * Generates input T1 tables.
     * 生成输入T1表
     */
    public void generateT1Tables() {
        // To initialize T1[1] map, coding map is needed, since it takes input from last round, for this we need key material
        // to add S-box to T1[1], so it is not done here...
        // 要初始化T1[1]映射，需要编码映射，
        // 因为它需要从最后一轮输入，为此我们需要关键原料将S-box添加到T1[1]，所以这里没有完成......
        int i, j;
        int b;

        final Bijection4x4[][] lfC = extc.getLfC();
        final LinearBijection[] IODM = extc.getIODM();
        State mapResult = new State();

        // At first initialize T1[0]
        // 先初始化T1[0]
        //
        for (i = 0; i < AES.BYTES; i++) {
            // i-th T1 table, indexed by cols
            // 第i个T1表，由列索引

            // Build tables - for each byte
            // 为每个字节生成表
            for (b = 0; b < 256; b++) {
                int bb = b;
                mapResult.zero();

                // Decode with IO encoding
                // 使用IO编码解码
                bb = HILO(lfC[0][2 * i + 1].invCoding[HI((byte)b)], lfC[0][2 * i + 0].invCoding[LO((byte)b)]) & 0xff;
                // Transform bb to matrix, to perform mixing bijection operation (matrix multiplication)
                // 将bb变换为矩阵，执行混合双射操作（即矩阵乘法）
                GF2MatrixEx tmpMat = new GF2MatrixEx(128, 1);
                // builds binary matrix [0 0 bb 0 0 0 0 0 0 0 0 0 0 0 0 0]^T, if i==2;
                // 当i==2，生成二进制矩阵[0 0 bb 0 0 0 0 0 0 0 0 0 0 0 0 0]^T
                NTLUtils.putByteAsColVector(tmpMat, (byte)bb, i * 8, 0);
                // Build MB multiplication result
                // 生成MB乘法结果
                tmpMat = (GF2MatrixEx) IODM[0].getInv().rightMultiply(tmpMat);
                // Encode 128-bit wide output to map result
                // 编码128位宽输出以映射结果
                for (j = 0; j < AES.BYTES; j++) {
                    mapResult.set(NTLUtils.colBinaryVectorToByte(tmpMat, 8 * j, 0), j);
                }
                // Encode mapResult with out encoding of T1 table
                // 使用T1表的编码对mapResult进行编码
                iocoding_encode128x128(mapResult, mapResult, AESMap.getT1()[0][i].getCod(), false, io.getpCoding04x04(), null);
                // Store result value to lookup table
                // 将结果值存储到查找表
                AESi.getT1()[0][i].setValue(mapResult, b);
            }
        }
    }

    /**
     * Simple routine to generate one XOR table.
     * 生成一个XOR表的简单例程
     * @param xorCoding
     * @param xtb
     */
    public static void generateXorTable(Coding xorCoding, byte[] xtb, Bijection4x4[] bio){
        for(int b=0; b<256; b++){
            int	bb = b;
            bb = iocoding_encode08x08((byte)bb, xorCoding.IC, true, bio, null);
            bb = HI((byte)bb) ^ LO((byte)bb);
            bb = iocoding_encode08x08((byte)bb, xorCoding.OC, false, bio, null);
            xtb[b] = (byte) bb;
        }
    }

    /**
     * Generates whole XOR cascade with 32bit input & output argument. No External 
     * encoding is used thus can be done here.
     * 生成具有32位输入和输出参数的整个XOR级联
     * 没有使用外部编码，因此可以直接完成
     */
    public void generateXorCascades(){
        final GXORCascade[][] xorMap = AESMap.getXor();
        XORCascade[][]  xor    = AESi.getXor();

        for(int r=0; r<AES.ROUNDS; r++){
            for(int i = 0; i<2* State.COLS; i++){
                xorMap[r][i].generateTables(xor[r][i], this);
            }
        }
    }

    /**
     * Generates whole XOR cascade with 128bit input & output argument.
     * 生成具有128位输入和输出参数的整个XOR级联
     *
     */
    public void generateXorStateCascades(){
        final GXORCascadeState[] xorMap = AESMap.getXorState();
        XORCascadeState[]  xor    = AESi.getXorState();

        xorMap[0].generateTables(xor[0], this);
        xorMap[1].generateTables(xor[1], this);
    }

    /**
     * Initializes internal structures prior generate().
     * Memory allocation, ...
     * 在generate（）之前初始化内部结构
     * 内存分配之类的...
     */
    public void initInternal(){
        AESh   = new AEShelper();
        AESi   = new AES();
        AESMap = new AESCodingMap();
        io     = new InternalBijections();

        // allocate memory needed
        // 分配内存
        // -System.out.println("Memory allocation...");
        AESi.init();
        AESMap.init();
        io.memoryAllocate();
    }

    /**
     * Generate whitebox AES tables.
     * 生成白盒AES查找表
     * @param encrypt
     * @param key
     * @param keySize
     * @param ex
     */
    public void generate(boolean encrypt, byte[] key, int keySize, ExternalBijections ex){
        this.initInternal();
        AESi.setEncrypt(encrypt);

        extc = ex;

        // -System.out.println("AES initialization");
        AESh.build(encrypt);
        final GF2mField field = AESh.getField();

        // Create coding map. This step is always constant for each AES
        // but can be modified during debuging new features (enable/disable bijections).
        // 创建编码图
        // 对于每个AES，此步骤始终是恒定的，但可以在调试新功能（启用/禁用双射）期间进行修改
        // -System.out.println("Coding map generation...");
        AESMap.setEncrypt(encrypt);
        AESMap.generateCodingMap();

        // set external encodings to XORCascadeState
        // 将外部编码设置为XORCascadeState
        AESMap.getXorState()[1].setExternalOut(extc.getLfC()[1]);

        // Allocate space for IO bijections
        // 为IO双射分配空间
        io.alloc04x04(AESMap.getIdx()+1);

        // Generate 4x4 IO bijections
        // 生成4x4 IO双射
        // -System.out.println("Generating IO bijections...");
        generate4X4Bijections(io.getpCoding04x04(), AESMap.getIdx()+1, useIO04x04Identity);

        // Generate mixing bijections
        // 生成混合双射
        // -System.out.println("Generating mixing bijections...");
        generateMixingBijections(io, MB_CNT_08x08_ROUNDS, MB_CNT_32x32_ROUNDS, useMB08x08Identity, useMB32x32Identity);

        // Init T1[0] tables - for the first round
        // -System.out.println("Generating first round tables (T1) ");
        generateT1Tables();

        // Generate round keys
        // -System.out.println("Computing key schedule ");
        byte[] keySchedule = AESh.keySchedule(key, keySize, debug);
        StringBuilder sb = new StringBuilder();
        for(int i=0; i<keySchedule.length; i++){
            sb.append(String.format("0x%02X", keySchedule[i]));
            sb.append((i>0 && (((i+1) % 16) == 0)) ? "\n" : ", ") ;
        }
        // -System.out.println(sb.toString());

        // Generate all XOR cascades
        // 生成所有XOR级联
        // -System.out.println("Generating all 32bit XOR tables");
        this.generateXorCascades();
        this.generateXorStateCascades();

        // Generate cipher based tables
        // 生成基于密码的表
        int i,j,k,b;
        // pre-load bijections
        // 预加载双射
        final LinearBijection[][] eMB_L08x08 = io.getMB_L08x08();
        final LinearBijection[][] eMB_MB32x32 = io.getMB_MB32x32();
        final GTBox8to128[][] t1C = AESMap.getT1();
        final GTBox8to32[][] t2C  = AESMap.getT2();
        final GTBox8to32[][] t3C  = AESMap.getT3();
        final Bijection4x4[] pCoding04x04 = io.getpCoding04x04();
        final Bijection8x8[] pCoding08x08 = null;
        final LinearBijection[] IODM = extc.getIODM();
        final Bijection4x4[][] lfC   = extc.getLfC();

        T1Box[][] t1 = AESi.getT1();
        T2Box[][] t2 = AESi.getT2();
        T3Box[][] t3 = AESi.getT3();

        // Precompute L lookup table, L_k stripes
        // 预计算L查找表，L_k条
        byte Lr_k_table[][] = new byte[State.COLS][256];
        GF2MatrixEx Lr_k[] = new GF2MatrixEx[State.COLS];

        // Generate tables for AES
        // 生成AES表
        for (int r = 0; r < AES.ROUNDS; r++) {
            // -System.out.println("Generating tables for round = " + (r + 1));

            // Iterate by mix cols/sections/dual AES-es
            // 通过列混合 / 段 / 双 AES-es迭代
            // i = current column in state matrix
            // i = 状态矩阵中的当前列
            for (i = 0; i < State.COLS; i++) {

                //
                // Build L lookup table from L_k stripes using shiftRowsLBijection (Lr_k is just simplification for indexes)
                // Now we are determining Lbox that will be used in next round.
                // Also pre-compute lookup tables by matrix multiplication.
                // j = current row in state matrix
                // 使用shiftRowsLBijection从L_k条带构建L查找表（Lr_k只是索引的简化）
                // 现在我们配置下一轮Lbox
                // 还通过矩阵乘法预先计算查找表
                // j = 状态矩阵中的当前行
                for (j = 0; r < (AES.ROUNDS - 1) && j < State.ROWS; j++) {
                    // 状态数组的索引，按列迭代
                    final int idx = j * State.COLS + i; // index to state array, iterating by cols;

                    Lr_k[j] = eMB_L08x08[r][nextTbox(idx, encrypt)].getMb();
                    for (b = 0; b < 256; b++) {
                        GF2MatrixEx tmpMat = new GF2MatrixEx(8, 1);
                        NTLUtils.putByteAsColVector(tmpMat, (byte) b, 0, 0);

                        // multiply with 8x8 mixing bijection to obtain transformed value
                        // 乘以8x8混合双射以获得变换值
                        tmpMat = (GF2MatrixEx) Lr_k[j].rightMultiply(tmpMat);

                        // convert back to byte value
                        // 转回字节的值
                        Lr_k_table[j][b] = NTLUtils.colBinaryVectorToByte(tmpMat, 0, 0);
                    }
                }

                //
                // T table construction (Type2, if r=last one, then T1); j iterates over rows
                // T表构造（二型表，如果r为最后一个，则为T1表）
                // j遍历行
                //
                for (j = 0; j < State.ROWS; j++) {
                    // 状态数组的索引，按列迭代
                    final int idx = j * State.COLS + i; // index to state array, iterating by cols;

                    // round key index
                    // 轮密钥索引
                    final int keyIdx = encrypt ?
                            16 * r                    + State.transpose(AES.shift(idx, encrypt))
                            : 16 * (AES.ROUNDS - r - 1) + State.transpose(idx);

                    // special first / last round key
                    // 特殊的第一轮/最后一轮钥匙
                    final int keyIdx2 = encrypt?
                            16 * (r + 1) + State.transpose(idx)
                            : 16 * AES.ROUNDS + State.transpose(AES.shift(idx, encrypt));

                    // -System.out.println((encrypt ? 'e': 'd')+"T[" + r + "][" + i + "][" + j + "] key = "
//                            + keyIdx
//                            + " = " + String.format("0x%02X", posIdx(keySchedule[keyIdx]))
//                            + "; idx=" + idx);

                    if ((!encrypt && r == 0) || (r == AES.ROUNDS - 1 && encrypt)) {
                        // -System.out.println((encrypt ? 'e': 'd')+"T[" + r + "][" + i + "][" + j + "]F key = "
//                                + keyIdx2 + " = " + String.format("0x%02X", posIdx(keySchedule[keyIdx2])));
                    }


                    // Build tables - for each byte
                    // 为每个字节构建表
                    for (b = 0; b < 256; b++) {
                        int tmpGF2E;
                        long mapResult;
                        GF2MatrixEx mPreMB;
                        GF2mMatrixEx mcres;
                        int bb = b;

                        // In the first round we apply codings from T1 tables.

                        // Decode input with IO coding
                        // For the last round, INPUT coding is for T1 box, otherwise for T2 box
                        // 在第一轮中，我们应用T1表中的编码
                        // 使用IO置换编码解码输入
                        // 最后一轮，输入编码归T1盒，否则就给T2盒
                        if (r < (AES.ROUNDS - 1)) {
                            bb = iocoding_encode08x08((byte) bb, t2C[r][idx].getCod().IC, true, pCoding04x04, pCoding08x08);
                        } else {
                            bb = iocoding_encode08x08((byte) bb, t1C[1][idx].getCod().IC, true, pCoding04x04, pCoding08x08);
                        }

                        tmpGF2E = bb;

                        //
                        // Mixing bijection - removes effect induced in previous round (inversion here)
                        // Note: for DualAES, data from prev round comes here in prev Dual AES encoding, with applied bijection
                        // on them. Reversal = apply inverse of mixing bijection, undo prev Dual AES, do cur Dual AES
                        // Scheme: Tapply_cur( TapplyInv_prev( L^{-1}_{r-1}(x) ) )
                        //
                        // Implementation: matrix multiplication in GF2.
                        // Inversion to transformation used in previous round in T3 box (so skip this in first round).
                        // 混合双射 - 消除前一轮诱导的效果（此处反转）
                        // 注意：对于对偶AES，前一轮的已应用双射的数据来自于双重AES编码
                        // 反转 = 应用混合双射的倒数，撤消前一个对偶AES，执行本次对偶AES
                        // 方案：Tapply_cur( TapplyInv_prev( L^{-1}_{r-1}(x) ) )
                        // 实现：GF2中的矩阵乘法。
                        // 在T3盒中的前一轮使用的转换反转（所以在第一轮跳过这个）
                        //
                        if (r > 0) {
                            GF2MatrixEx tmpMat = new GF2MatrixEx(8, 1);
                            NTLUtils.putByteAsColVector(tmpMat, (byte) tmpGF2E, 0, 0);

                            tmpMat = (GF2MatrixEx) eMB_L08x08[r - 1][idx].getInv().rightMultiply(tmpMat);
                            tmpGF2E = NTLUtils.colBinaryVectorToByte(tmpMat, 0, 0);
                        }

                        //
                        // Encryption scenario:
                        // Build T_i box by composing with round key
                        //
                        // White box implementation:
                        // shiftRows(state)
                        // addRoundKey(state, shiftRows(ApplyT(K_{r-1}))) when indexing rounds from 1 and key from 0
                        //   K_{r-1} is AES key for default AES,
                        //   apply = linear transformation (multiplication by matrix T from dual AES) for changing default AES to dual AES.
                        //
                        // Rewritten to form:
                        // shiftRows(state)
                        // addRoundKey(state, ApplyT(shiftRows(K_r)))
                        //
                        // K_{r}  [x][y] = keySchedule[r][i] [16*(r)   + x*4 + y]
                        // in this round we want to work with AES from same dual AES, thus we are choosing
                        // keySchedule[r][i]. Also we have to take effect of ShiftRows() into account, thus apply
                        // ShiftRows() transformation on key indexes.
                        //
                        // Implementation in one section (i) corresponds to one column (0,5,10,15) are indexes taken
                        // for computation in one section in WBAES. Inside section (column) we are iterating over
                        // rows (j). Key is serialized by rows.
                        // 加密方案：
                        // T_i盒由轮密钥构建
                        //
                        // 白盒实现
                        // shiftRows(state)
                        // addRoundKey(state, shiftRows(ApplyT(K_{r-1}))) 轮次从1开始，子密钥从0开始索引
                        //  K_ {r-1}是默认AES的AES密钥
                        //  apply为线性变换（从对偶AES中乘以矩阵T），将朴素AES更改为对偶AES
                        // 重写格式：
                        // shiftRows(state)
                        // addRoundKey(state, ApplyT(shiftRows(K_r)))
                        //
                        // K_{r}  [x][y] = keySchedule[r][i] [16*(r)   + x*4 + y]
                        // 这一轮中，我们希望对偶AES与AES等效，因此这里选择keySchedule[r][i]
                        // 此外，我们必须考虑ShiftRows()的效果，因此对关键索引进行ShiftRows()转换
                        // 在一个部分的i中的实现对应于一列(0,5,10,15)是在WBAES中的一个部分中计算的索引
                        // 在内部部分（列）中，我们遍历行（j）
                        // 子密钥按行序列化
                        //

                        if (encrypt) {
                            int tmpKey = keySchedule[keyIdx];
                            tmpGF2E = field.add(tmpGF2E & 0xff, tmpKey & 0xff) & 0xff;
                        } else {
                            if (r == 0) {
                                // Decryption & first round => add k_10 to state.
                                // Same logic applies here
                                // AddRoundKey(State, k_10)  | -> InvShiftRows(State)
                                // InvShiftRows(State)       | -> AddRoundKey(State, InvShiftRows(k_10))
                                // 解密和第一轮=>将k_10添加到状态
                                // 同样的逻辑也适用于这里
                                // AddRoundKey(State, k_10)  | -> InvShiftRows(State)
                                // InvShiftRows(State)       | -> AddRoundKey(State, InvShiftRows(k_10))
                                int tmpKey = keySchedule[keyIdx2];
                                tmpGF2E = field.add(tmpGF2E & 0xff, tmpKey & 0xff) & 0xff;
                            }
                        }

                        // SBox transformation with dedicated AES for this round and section
                        // Encryption: ByteSub
                        // Decryption: ByteSubInv
                        // 针对此轮次和部分使用专用AES进行SBox转换
                        // 加密：ByteSub
                        // 解密：ByteSubInv
                        int tmpE = encrypt ? AESh.ByteSub(tmpGF2E) : AESh.ByteSubInv(tmpGF2E);

                        // Decryption case:
                        // 解密部分
                        // T(x) = Sbox(x) + k
                        if (!encrypt) {
                            tmpE = field.add(tmpE & 0xff, keySchedule[keyIdx] & 0xff) & 0xff;
                        }

                        // If we are in last round we also have to add k_10, not affected by ShiftRows()
                        // And more importantly, build T1
                        // 最后一轮，必须添加k_10，无ShiftRows()，并构建T1盒
                        //
                        if (r == AES.ROUNDS - 1) {
                            // Adding last encryption key (k_10) by special way is performed only in encryption
                            // 通过特殊方式添加最后一个的加密密钥(k_10)仅在加密中执行
                            if (encrypt) {
                                tmpE = field.add(tmpE & 0xff, keySchedule[keyIdx2] & 0xff) & 0xff;
                            }

                            // Now we use output encoding G and quit, no MixColumn or Mixing bijections here.
                            // 现在我们在这里使用输出编码G并退出，没有MixColumn或混合双射
                            State mapResult128 = new State();
                            bb = tmpE;

                            // Transform bb to matrix, to perform mixing bijection operation (matrix multiplication)
                            // 将bb变换为矩阵，执行混合双射操作（矩阵乘法）
                            GF2MatrixEx tmpMat2 = new GF2MatrixEx(128, 1);
                            // builds binary matrix [0 0 bb 0 0 0 0 0 0 0 0 0 0 0 0 0], if curByte==2
                            // 当curByte == 2，构建二进制矩阵[0 0 bb 0 0 0 0 0 0 0 0 0 0 0 0 0]
                            NTLUtils.putByteAsColVector(tmpMat2, (byte) bb, (i * State.COLS + j) * 8, 0);
                            // Build MB multiplication result
                            // 构建MB乘法结果
                            tmpMat2 = (GF2MatrixEx) IODM[1].getMb().rightMultiply(tmpMat2);
                            // Encode 128-bit wide output to map result
                            // 编码128位输出以映射结果
                            for (int jj = 0; jj < 16; jj++) {
                                mapResult128.set(NTLUtils.colBinaryVectorToByte(tmpMat2, jj * 8, 0), jj);
                            }
                            // Encode mapResult with out encoding of T1 table
                            // 使用T1表的编码对mapResult进行编码
                            iocoding_encode128x128(mapResult128, mapResult128, t1C[1][idx].getCod(), false, pCoding04x04, pCoding08x08);
                            // Store result value to lookup table
                            // 将结果值存储到查找表
                            t1[1][idx].getTbl()[b].setState(mapResult128.getState());
                            continue;
                        }

                        //
                        // MixColumn, Mixing bijection part
                        //	only in case 1..9 round
                        // MixColumn和混合双射部分只在1到9轮进行

                        // Build [0 tmpE 0 0]^T stripe where tmpE is in j-th position
                        // 构建[0 tmpE 0 0] ^ T列，其中tmpE在第j个位置
                        GF2mMatrixEx zj = new GF2mMatrixEx(field, 4, 1);
                        zj.set(j, 0, tmpE);

                        // Multiply with MC matrix from our AES dedicated for this round, only in 1..9 rounds (not in last round)
                        // 与我们专用于此轮的AES中的MC矩阵相乘，仅在1到9轮（不是在最后一轮）
                        if (encrypt) {
                            mcres = r < (AES.ROUNDS - 1) ? AESh.getMixColMat().rightMultiply(zj) : zj;
                        } else {
                            mcres = r < (AES.ROUNDS - 1) ? AESh.getMixColInvMat().rightMultiply(zj) : zj;
                        }

                        // Apply 32x32 Mixing bijection, mPreMB is initialized to GF2MatrixEx with 32x1 dimensions,
                        // 应用32x32混合双射，mPreMB初始化为GF2MatrixEx，尺寸为32x1，
                        // GF2E values are encoded to binary column vectors
                        // GF2E值被编码为二进制列向量
                        mPreMB = NTLUtils.GF2mMatrix_to_GF2Matrix_col(mcres, 8);
                        mPreMB = (GF2MatrixEx) eMB_MB32x32[r][i].getMb().rightMultiply(mPreMB);

                        //
                        // TESTING - multiply by inversion
                        // 测试 - 乘以反演
                        // Convert transformed vector back to values
                        // 将变换后的矢量转换回值
                        mapResult = NTLUtils.GF2Matrix_to_long(mPreMB, 0, 0);

                        // Encode mapResult with out encoding
                        // 使用out编码对mapResult进行编码
                        mapResult = iocoding_encode32x32(mapResult, t2C[r][idx].getCod(), false, pCoding04x04, pCoding08x08);
                        // Store result value to lookup table
                        // 将结果值存储到查找表
                        t2[r][idx].getTbl()[b] = mapResult;
                    }
                }

                // In final round there are no more XOR and T3 boxes
                // 在最后一轮中，不再有XOR和T3盒
                if (r == AES.ROUNDS - 1) {
                    continue;
                }

                //
                // B table construction (Type3) - just mixing bijections and L strip
                // B表结构（三型表） - 含混合双射和L列
                //
                for (j = 0; j < State.COLS; j++) {
                    final int idx = j * State.COLS + i; // index to state array, iterating by cols;

                    // Build tables - for each byte
                    // 为每个字节构建表
                    for (b = 0; b < 256; b++) {
                        long mapResult;
                        int bb = b;
                        // Decode with IO encoding
                        // IO 编码解码
                        bb = iocoding_encode08x08((byte) b, t3C[r][idx].getCod().IC, true, pCoding04x04, pCoding08x08);
                        // Transform bb to matrix, to perform mixing bijection operation (matrix multiplication)
                        // 将bb变换为矩阵，执行混合双射操作（矩阵乘法）
                        GF2MatrixEx tmpMat = new GF2MatrixEx(32, 1);
                        // builds binary matrix [0 0 bb 0], if j==2
                        // 如果j == 2，则构建二进制矩阵[0 0 bb 0]
                        NTLUtils.putByteAsColVector(tmpMat, (byte) bb, j * 8, 0);
                        // Build MB multiplication result
                        // 构建MB乘法结果
                        tmpMat = (GF2MatrixEx) eMB_MB32x32[r][i].getInv().rightMultiply(tmpMat);
                        // Encode using L mixing bijection (another matrix multiplication)
                        // 使用L混合双射进行编码（另一种矩阵乘法）
                        // Map bytes from result via L bijections
                        // 通过L双射来映射结果中的字节
                        mapResult = 0;
                        mapResult |= Utils.byte2long(Lr_k_table[0][posIdx(NTLUtils.colBinaryVectorToByte(tmpMat, 8 * 0, 0))], 0);
                        mapResult |= Utils.byte2long(Lr_k_table[1][posIdx(NTLUtils.colBinaryVectorToByte(tmpMat, 8 * 1, 0))], 1);
                        mapResult |= Utils.byte2long(Lr_k_table[2][posIdx(NTLUtils.colBinaryVectorToByte(tmpMat, 8 * 2, 0))], 2);
                        mapResult |= Utils.byte2long(Lr_k_table[3][posIdx(NTLUtils.colBinaryVectorToByte(tmpMat, 8 * 3, 0))], 3);
                        // Encode mapResult with out encoding
                        // 使用输出编码对mapResult进行编码
                        mapResult = iocoding_encode32x32(mapResult, t3C[r][idx].getCod(), false, pCoding04x04, pCoding08x08);
                        // Store result value to lookup table
                        // 将结果值存储到查找表
                        t3[r][idx].getTbl()[posIdx(b)] = mapResult;
                    }
                }
            }
        }
    }

    /**
     * Applies external encoding to state - simulates environment.
     * 将外部编码应用于状态 - 模拟环境
     * @param state
     * @param extc
     * @param input
     */
    public void applyExternalEnc(State state, ExternalBijections extc, boolean input){
        assrt(extc!=null);
        if (input){
            // If input -> at first apply linear transformation 128 x 128, then bijection
            // Now we use output encoding G and quit, no MixColumn or Mixing bijections here.
            // 如果输入 - >首先应用128 x 128的线性变换，然后是双射
            // 现在我们在这里使用输出编码G并退出，没有MixColumn或混合双射
            //
            // Mixing bijection 128x128
            // 混合双射128x128
            //
            GF2MatrixEx tmpMat2 = new GF2MatrixEx(128, 1);
            for(int jj=0; jj<16; jj++){
                NTLUtils.putByteAsColVector(tmpMat2, state.get(jj), jj*8, 0);
            }

            tmpMat2 = (GF2MatrixEx) extc.getIODM()[0].getMb().rightMultiply(tmpMat2);

            for(int jj=0; jj<16; jj++){
                state.set(NTLUtils.colBinaryVectorToByte(tmpMat2, jj*8, 0), jj);
            }

            //
            // IO bijection
            // IO双射
            //
            for(int jj=0; jj<16; jj++){
                byte bLO = (byte) (extc.getLfC()[0][2*jj+0].coding[LO(state.get(jj))] & 0xff);
                byte bHI = (byte) (extc.getLfC()[0][2*jj+1].coding[HI(state.get(jj))] & 0xff);
                state.set((byte) HILO(bHI, bLO), jj);
            }
        } else {
            // Output -> decode bijections
            // 输出 ->解码映射

            //
            // IO bijection
            // IO双射
            //
            for(int jj=0; jj<16; jj++){
                byte bLO = (byte) (extc.getLfC()[1][2*jj+0].invCoding[LO(state.get(jj))] & 0xff);
                byte bHI = (byte) (extc.getLfC()[1][2*jj+1].invCoding[HI(state.get(jj))] & 0xff);
                state.set((byte) HILO(bHI, bLO), jj);
            }

            //
            // Mixing bijection 128x128
            // 混合双射128x128
            //
            GF2MatrixEx tmpMat2 = new GF2MatrixEx(128, 1);
            for(int jj=0; jj<16; jj++){
                NTLUtils.putByteAsColVector(tmpMat2, state.get(jj), jj*8, 0);
            }

            tmpMat2 = (GF2MatrixEx) extc.getIODM()[1].getInv().rightMultiply(tmpMat2);

            for(int jj=0; jj<16; jj++){
                state.set(NTLUtils.colBinaryVectorToByte(tmpMat2, jj*8, 0), jj);
            }
        }
    }

    public String chex(int l){
        return String.format("0x%08X", l);
    }

    public String chex(byte l){
        return String.format("0x%02X", l & 0xff);
    }

    public AES getAESi() {
        return AESi;
    }

    public void setAESi(AES AESi) {
        this.AESi = AESi;
    }

    public ExternalBijections getExtc() {
        return extc;
    }

    public void setExtc(ExternalBijections extc) {
        this.extc = extc;
    }

    public boolean isDebug() {
        return debug;
    }

    public void setDebug(boolean debug) {
        this.debug = debug;
    }

    public SecureRandom getRand() {
        return rand;
    }

    public void setRand(SecureRandom rand) {
        this.rand = rand;
    }

    public boolean isUseIO04x04Identity() {
        return useIO04x04Identity;
    }

    public void setUseIO04x04Identity(boolean useIO04x04Identity) {
        this.useIO04x04Identity = useIO04x04Identity;
    }

    public boolean isUseIO08x08Identity() {
        return useIO08x08Identity;
    }

    public void setUseIO08x08Identity(boolean useIO08x08Identity) {
        this.useIO08x08Identity = useIO08x08Identity;
    }

    public boolean isUseMB08x08Identity() {
        return useMB08x08Identity;
    }

    public void setUseMB08x08Identity(boolean useMB08x08Identity) {
        this.useMB08x08Identity = useMB08x08Identity;
    }

    public boolean isUseMB32x32Identity() {
        return useMB32x32Identity;
    }

    public void setUseMB32x32Identity(boolean useMB32x32Identity) {
        this.useMB32x32Identity = useMB32x32Identity;
    }

    public AESCodingMap getAESMap() {
        return AESMap;
    }

    public InternalBijections getIo() {
        return io;
    }

}
