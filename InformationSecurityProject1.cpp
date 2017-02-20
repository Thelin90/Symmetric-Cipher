#include <stdio.h>
#include <cstdlib>
#include <iostream>

/**
 *
 * Information Security Project 1, Implemented in C++ because of faster computation time and better handling of big values
 *
 * The S-box used in this code is taken from https://en.wikipedia.org/wiki/Rijndael_S-box
 * The code is programmed and debugged with Code::Blocks
 *
 * The approach of the code is the hard way, and it takes time. The KEY for the assignments:
 *
 * Find the key for:
 * E(K, 0x0123456789AB) = 0xFBD040D6DB9C -> K = 0x3e76ac4c
 * E(K, 0x9A6BCC10E84A) = 0xE5CBFFF7E08B -> K = 0x3e76ac4c
 *
 * @author Simon Thelin
 * @version 2.5
 * @date 2016-10-21
 */

const int KEYSIZE_BITS = 32;
const int BLOCKSIZE_BITS = 48;
const int TOT_ROUNDS = 11;
const int W_LENGTH = 17;
const long xF2 = 0xFF;
const long xF6 = 0xFFFFFF;
const long xF8 = 0xFFFFFFFF;
const long xF12 = 0xFFFFFFFFFFFF;
const long M[9] = {0x01,0x02,0x02,0x02,0x02,0x01,0x02,0x01,0x02};

bool flag1 = false, flag2 = false;
int shift_length = 0, shift_position = 0;

unsigned char s[256] =
{
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

/**
* The method set the shift length used in the rotl_shift method
*/
void setShiftLength(int l)
{
    shift_length = l;
}

/**
* The method set the shift position used in the rotl_shift method
*/
void setShiftPosition(int p)
{
    shift_position = p;
}

/**
* The method return the shift position used in the rotl_shift method
* @return the integer shift position
*/
int getShiftPosition()
{
    return shift_position;
}

/**
* The method return the shift length used in the rotl_shift method
* @return the integer shift length
*/
int getShiftLength()
{
    return shift_length;
}

/**
* This method performs addition, in this case with GF(2)
* where addition is exclusive OR (XOR).
*
* @return Bitwise XOR (exclusive or) of x and y
*/
long addition_Gallois(long x, long y)
{
    return x ^ y;
}

/**
 * Multiplication is performed modulo 2^8
 * Code is found at https://en.wikipedia.org/wiki/Finite_field_arithmetic
 * @return finite field multiplication of a and b
 */
long multGallois(long a, long b)
{
    long p = 0;
    while (b)
    {
        if (b & 1)
        {
            p ^= a;
        }
        if (a & 0x80)
        {
            a = (a << 1) ^ 0x11b;
        }
        else
        {
            a <<= 1;
        }
        b >>= 1;
    }
    return p;
}

/**
 * Circular left shift of key k by pos, performed during the steps,
 * first compound assignment with modolu from right to left, then shift
 * the (length - position) to the upperPart. Then with the compound assignment
 * shift left to the result. Then compound assigntment with or. N-bit circular left shift.
 *
 * @return the result from the circular shift
 */
long rotl_shift(long result)
{
    long upperPart = 0;

    setShiftPosition((getShiftPosition() % getShiftLength()));
    upperPart = (result >> (getShiftLength() - getShiftPosition()));
    result = (result << getShiftPosition());
    result = (result | upperPart);
    return result;
}

/**
* The method align make sure the keys are aligned, used in
* the process of W.
* @return the result from the align
*/
long* align(long* arr, long* res, int k_size)
{
    int temp = 0;
    for(int i = 0; i < k_size; i = i + 2)
    {
        res[i] = (arr[temp] << KEYSIZE_BITS / 2) | (arr[temp+1] >> (KEYSIZE_BITS / 2));
        res[i+1] = (((arr[temp+1] & 0xFFFF) << KEYSIZE_BITS) | arr[temp+2]);
        temp = temp + 3;
    }
    return res;
}

/**
* The method generates W from the masterkey with help of the
* circular shift of rotl_shift and the align method.
*/
long* generate_W(long* key, int keysize, long masterkey)
{
    long W_expanded[W_LENGTH];
    for(int i=0; i < W_LENGTH; i++)
    {
        setShiftLength(KEYSIZE_BITS);
        setShiftPosition((5*i) % KEYSIZE_BITS);
        W_expanded[i] = rotl_shift(masterkey) & xF8;
    }
    align(W_expanded,key,keysize);
}

/**
 * Multiply matrix M with state matrix vector
 * @param threeBytes state matrix vector
 * @param M ColumnMix matrix
 * @return long*
 */
long* matrix_multi(long* result, long m_shifted)
{
    long b_one = 0, b_two = 0, b_three = 0, threeBytes = 0
    , res_p1, res_p2, res_p3;

    for(int j = 0; j < 2; j++)
    {
        threeBytes = m_shifted & xF6;
        m_shifted = m_shifted >> 24;

        b_one = threeBytes & xF2;
        b_two = (threeBytes >> 8) & xF2;
        b_three = (threeBytes >> 16) & xF2;

        int i = 0;
        while(i <= 3)
        {
            res_p1 = multGallois(M[i*3], b_one);
            res_p2 = multGallois(M[i*3+1], b_two);
            res_p3 = multGallois(M[i*3+2], b_three);
            result[i+3*j] = addition_Gallois(res_p1, addition_Gallois(res_p2, res_p3));
            i++;
        }
    }
    return result;
}

/**
* The method sub the bytes with the help from the S-box.
* @return long
*/
long sub_byte(long the_state, int inputSize)
{
    long result = 0;
    long sboxvalue = 0;
    long x = 0, y = 0;
    for(int i = 0; i < inputSize; i++)
    {
        y = the_state & 0xF;
        x = (the_state >> 4) & 0xF;
        sboxvalue = (s[x*16 + y]);
        result = result | (sboxvalue << (8*i));
        the_state >>= 8;
    }
    return result;
}

/**
* The method encrypt handles the encryption, according to the instructions.
* Handled the key expansion for each key with 48 bit, XOR the input of the key,
* sub the bytes from the XOR operation, shift the rows, muliply the result.
* Do the final shifts and return the result with an XOR from the big key at position 10.
*
* @return the final ciphertext
*/
long encrypt(long key, long input)
{
    long m_state_shifted = 0, m_state = 0, state = 0;
    long result[6];
    long bigKey[TOT_ROUNDS];
    generate_W(bigKey, TOT_ROUNDS, key);

    for(int i = 0; i < TOT_ROUNDS-1; i++)
    {
        state = input ^ bigKey[i];
        m_state = sub_byte(state,6);

        setShiftLength(BLOCKSIZE_BITS);
        setShiftPosition(8);

        m_state_shifted = rotl_shift(m_state) & xF12;

        matrix_multi(result, m_state_shifted);

        input = (result[4]<<40) | (result[3] << 32);
        input = input | (result[5]<<24) | (result[1] << 16);
        input = input | result[0] << 8 | result[2];

    }

    long ret_finalValIndex = TOT_ROUNDS-1;

    return input ^ bigKey[ret_finalValIndex];
}

/**
* The method check if the cipher matches question1
*/
void checkAnswer1(long cipher_1)
{
    if(cipher_1 == 0xFBD040D6DB9C)
    {
        flag1 = true;
    }
    else
    {
        flag1 = false;
    }
}

/**
* The method check if the cipher matches question2
*/
void checkAnswer2(long cipher_2)
{
    if(cipher_2 == 0xE5CBFFF7E08B)
    {
        flag2 = true;
    }
    else
    {
        flag2 = false;
    }
}

/**
* Main method for the application, prints the result when reached. Takes a while but will result in:
* E(K, 0x0123456789AB) = 0xFBD040D6DB9C -> K = 0x3e76ac4c
* E(K, 0x9A6BCC10E84A) = 0xE5CBFFF7E08B -> K = 0x3e76ac4c
*
* Created search_for_key_val for a faster search, this through try and error (many, many, many hours...)
*/
int main(int argc, char *argv[])
{
    argc = 2;
    long cipher1, cipher2;
    long search_for_key_val = 0x3DEEEFFF;

    for(long i = search_for_key_val; i < xF8; i++)
    {
        if(flag1 == true)
        {
            std::cout << "================================================================\n";
            std::cout << "Correct Hexadecimal: ";
            std::cout << std::showbase << std::hex;
            std::cout << std::uppercase << cipher1 << '\n';
            std::cout << "Correct Decimal: ";
            std::cout << std::showbase << std::dec;
            std::cout << cipher1 << '\n';
            std::cout << "Correct Key: ";
            std::cout << std::showbase << std::hex;
            std::cout << i << '\n';
            std::cout << "================================================================\n";
            break;
        }
        else
        {
             //FOR DEBUGG ONLY
                std::cout << "Testing Key: ";
                std::cout << std::showbase << std::hex;
                std::cout << i << '\n';
                std::cout << "...wrong\n";
                std::cout << "================================================================\n";

        }
        cipher1 = encrypt(i, 0x0123456789AB);
        checkAnswer1(cipher1);
    }

    for(long j = search_for_key_val; j < xF8; j++)
    {
        if(flag2 == true)
        {
            std::cout << "================================================================\n";
            std::cout << "Correct Hexadecimal: ";
            std::cout << std::showbase << std::hex;
            std::cout << std::uppercase << cipher2 << '\n';
            std::cout << "Correct Decimal: ";
            std::cout << std::showbase << std::dec;
            std::cout << cipher2 << '\n';
            std::cout << "Correct Key: ";
            std::cout << std::showbase << std::hex;
            std::cout << j << '\n';
            std::cout << "================================================================\n";
            break;
        }
        else
        {
            /* //FOR DEBUGG ONLY
                std::cout << "Testing Key: ";
                std::cout << std::showbase << std::hex;
                std::cout << j << '\n';
                std::cout << "...wrong\n";
                std::cout << "================================================================\n";
                */
        }
        cipher2 = encrypt(j, 0x9A6BCC10E84A);
        checkAnswer2(cipher2);
    }
    return 0;
}
