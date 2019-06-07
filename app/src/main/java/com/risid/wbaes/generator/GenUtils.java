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

import java.security.SecureRandom;

/**
 *
 * @author ph4r05
 */
public class GenUtils {
    
    private SecureRandom rand;

    public GenUtils() {
    }

    public GenUtils(SecureRandom rand) {
        this.rand = rand;
    }
    
    /**
     * Generates random permutation of an integer array of given size.
     * Initializes the array if int>0.
     * 生成给定大小的整数数组的随机排列。 如果int> 0，则初始化数组。
     * @param bijection
     * @param size
     * @param init
     * @return 
     */
    public int randomPermutation(int[] bijection, int size, int init){
        int i;
        if (init >= 0) {
            for (i = 0; i < size; i++) {
                bijection[i] = i + init;
            }
        }

        return randomPermutation(bijection, size);
    }
    
    /**
     * Generates random permutation of integer array of given size.
     * Secure random is provided by class.
     * 生成给定大小的整数数组的随机排列
     * 安全随机由类提供
     * @param bijection
     * @param size
     * @return 
     */
    public int randomPermutation(int[] bijection, int size){
        return randomPermutation(bijection, size, rand);
    }
    
    /**
     * Generates random permutation of integer array of given size.
     * Secure random is provided by user.
     * 生成给定大小的整数数组的随机排列
     * 安全随机由用户提供
     * @param bijection
     * @param size
     * @param rand
     * @return 
     */
    public static int randomPermutation(int[] bijection, int size, SecureRandom rand){
        // yes, we start from second element on purpose, to produce uniform distribution
        // 从第二个元素开始，以产生均匀分布
        for (int i = 1; i < size; i++) {
            // rnd is index from interval [0, i]
            // rnd是区间[0,i]的索引
            int rnd = rand.nextInt(i + 1);

            // swap values
            // 交换值
            int tmp = bijection[rnd];
            bijection[rnd] = bijection[i];
            bijection[i] = tmp;
        }

        return 0;
    }
    
    public <T> int randomPermutation(T[] bijection, int size){
        return randomPermutation(bijection, size, rand);
    }
    
    /**
     * Generates random permutation of given generic array.
     * 生成给定通用数组的随机排列
     * @param <T>
     * @param bijection
     * @param size
     * @param rand
     * @return 
     */
    public static <T> int randomPermutation(T[] bijection, int size, SecureRandom rand){
        // yes, we start from second element on purpose, to produce uniform distribution
        // 从第二个元素开始，以产生均匀分布
        for (int i = 1; i < size; i++) {
            // rnd is index from interval [0, i]
            int rnd = rand.nextInt(i + 1);

            // swap values
            // 交换值
            T tmp = bijection[rnd];
            bijection[rnd] = bijection[i];
            bijection[i] = tmp;
        }

        return 0;
    }
    
    /**
     * Generates random bijection and its inverse on integer type of given size.
     * Secure random is provided by class.
     * 生成随机双射及其对给定大小的整数类型的逆
     * 由类提供安全的随机数
     * 
     * @param bijection
     * @param inverse
     * @param size
     * @param init
     * @param rand
     * @return 
     */
    public int generateRandomBijection(int[] bijection, int[] inverse, int size, boolean init){
        return generateRandomBijection(bijection, inverse, size, init, rand);
    }
    
    /**
     * Generates random bijection and its inverse on integer type of given size.
     * Secure random is provided by user.
     * 生成随机双射及其对给定大小的整数类型的逆
     * 由用户提供安全的随机数
     * @param bijection
     * @param inverse
     * @param size
     * @param init
     * @param rand
     * @return 
     */
    public static int generateRandomBijection(byte[] bijection, byte[] inverse, int size, boolean init, SecureRandom rand){
	int i;
        if (init) {
            for (i = 0; i < size; i++) {
                bijection[i] = (byte)i;
                inverse[i] = (byte)i;
            }
        }

        // yes, we start from second element on purpose, to produce uniform distribution
        // 保证随机
        for (i = 1; i < size; i++) {
            // rnd is index from interval [0, i]
            // rnd是区间[0, i]的索引
            int rnd = rand.nextInt(i + 1);

            // swap indexes
            // 交换索引
            byte idx = inverse[bijection[rnd]];
            inverse[bijection[rnd]] = inverse[bijection[i]];
            inverse[bijection[i]] = idx;

            // swap values
            // 交换值
            byte tmp = bijection[rnd];
            bijection[rnd] = bijection[i];
            bijection[i] = tmp;
        }

        return 0;
    }
    
    /**
     * Generates random bijection and its inverse on integer type of given size.
     * Secure random is provided by user.
     * 生成随机双射及其对给定大小的整数类型的逆
     * 由用户提供安全的随机数
     * @param bijection
     * @param inverse
     * @param size
     * @param init
     * @param rand
     * @return 
     */
    public static int generateRandomBijection(int[] bijection, int[] inverse, int size, boolean init, SecureRandom rand){
	int i;
        if (init) {
            for (i = 0; i < size; i++) {
                bijection[i] = i;
                inverse[i] = i;
            }
        }

        // yes, we start from second element on purpose, to produce uniform distribution
        for (i = 1; i < size; i++) {
            // rnd is index from interval [0, i]
            int rnd = rand.nextInt(i + 1);

            // swap indexes
            int idx = inverse[bijection[rnd]];
            inverse[bijection[rnd]] = inverse[bijection[i]];
            inverse[bijection[i]] = idx;

            // swap values
            int tmp = bijection[rnd];
            bijection[rnd] = bijection[i];
            bijection[i] = tmp;
        }

        return 0;
    }

    public SecureRandom getRand() {
        return rand;
    }

    public void setRand(SecureRandom rand) {
        this.rand = rand;
    }
    
   
}
