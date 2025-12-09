using ImGuiNET;
using System;
using System.Text;
using System.Security.Cryptography;
using System.Numerics;

partial class Program
{
    public string inputText = ""; 
    public string encryptedOutput = ""; 
    public string Key = ""; 

    private Encrypt encrypt;
    private ReEncrypt reEncrypt;

    protected override void Render()
    {

        ImGui.Begin("Шифр одноалфавитной замены"); 
        
        if (ImGui.Button("Выход"))
            Close(); 

        ImGui.Separator(); 

        ImGui.Text("Шифр квадрат Виженера");
        ImGui.Text("Введите текст для зашифровки / дешифровки пишется слитно");
        ImGui.Text("(только русские буквы)");
        ImGui.InputTextMultiline("Исходный текст", ref inputText, 1000, new Vector2(-1, ImGui.GetTextLineHeightWithSpacing() * 5));
        ImGui.Text("Введите ключевое слово");
        //ImGui.SliderInt("Сдвиг (шаг)", ref Key, 1, 32 , $"Шаг: %d");
        ImGui.InputText("Введите секретный ключ", ref Key, 16);

        ImGui.Spacing();

        if (ImGui.Button("Зашифровать"))
        {
           encrypt = new Encrypt (Key);
           encryptedOutput = encrypt.Execute(inputText);
        }
        ImGui.SameLine(); 
        if (ImGui.Button("Дешифровать"))
        {
            reEncrypt = new ReEncrypt(Key);
            encryptedOutput = reEncrypt.Execute(inputText);
        }

        ImGui.Separator(); 

        ImGui.Text("Результат:");
        ImGui.InputTextMultiline("Зашифрованный / Дешифрованный текст", ref encryptedOutput, (uint)encryptedOutput.Length + 100, new Vector2(-1, ImGui.GetTextLineHeightWithSpacing() * 5));
        
        ImGui.End();
    }
}
public class Encrypt
{
    private const int b = 32;           
    private const int bytesPerWord = b / 8;
    private const int R = 12 ;           
    private const int L = 16;            
    private const int t = 2 * (R + 1);  
    private readonly uint[] Q; 
    public Encrypt(string inputKey)
    {
        if (inputKey == null) inputKey = "";
        byte[] keyBytes = Encoding.UTF8.GetBytes(inputKey);
        byte[] key = new byte[L];
        int copyLen = Math.Min(keyBytes.Length, L);
        Array.Copy(keyBytes, key, copyLen);
        Q = KeySchedule(key);
    }
     private uint[] KeySchedule(byte[] key)
    {
        int c = (key.Length + bytesPerWord - 1) / bytesPerWord;
        uint[] L = new uint[c];
        for (int i = key.Length - 1; i >= 0; i--)
        {
            L[i / bytesPerWord] = (L[i / bytesPerWord] << 8) + key[i];
        }
        uint[] S = new uint[t];
        uint P = 0xb7e15163u;
        uint Qc = 0x9e3779b9u;
        S[0] = P;
        for (int i = 1; i < t; i++)
        {
            S[i] = S[i - 1] + Qc;
        }
        int n = Math.Max(t, c);
        uint A = 0, B = 0;
        int iIndex = 0, j = 0;
        for (int k = 0; k < 3 * n; k++)
        {
            A = S[iIndex] = RotateLeft(S[iIndex] + A + B, 3);
            B = L[j] = RotateLeft(L[j] + A + B, (int)((A + B) % 32));
            iIndex = (iIndex + 1) % t;
            j = (j + 1) % c;
        }
        return S;
    }

     public string Execute(string messege)
    {
        if (messege == null) messege = "";

        byte[] plain = Encoding.UTF8.GetBytes(messege);
        int blockSize = 8;
        int pad = (blockSize - (plain.Length % blockSize)) % blockSize;
        byte[] data = new byte[plain.Length + pad];
        Array.Copy(plain, data, plain.Length);

        byte[] cipher = new byte[data.Length];
        for (int i = 0; i < data.Length; i += blockSize)
        {
            byte[] block = new byte[blockSize];
            Array.Copy(data, i, block, 0, blockSize);
            byte[] enc = EncryptBlock(block);
            Array.Copy(enc, 0, cipher, i, blockSize);
        }
        return Convert.ToBase64String(cipher);
    }

     private static uint RotateLeft(uint x, int y)
    {
        int s = y & 31;
        return (x << s) | (x >> (32 - s));
    }

    private byte[] EncryptBlock(byte[] block)
    {
        uint A = BitConverter.ToUInt32(block, 0);
        uint B = BitConverter.ToUInt32(block, 4);
        A = A + Q[0];
        B = B + Q[1];
        for (int i = 1; i <= R; i++)
        {
            A = RotateLeft(A ^ B, (int)(B % 32)) + Q[2 * i];
            B = RotateLeft(B ^ A, (int)(A % 32)) + Q[2 * i + 1];
        }
        byte[] outBlock = new byte[8];
        Array.Copy(BitConverter.GetBytes(A), 0, outBlock, 0, 4);
        Array.Copy(BitConverter.GetBytes(B), 0, outBlock, 4, 4);
        return outBlock;
    }
}

public class ReEncrypt
{
      private const int b = 32;           
    private const int bytesPerWord = b / 8;
    private const int R = 12;           
    private const int l = 16;            
    private const int t = 2 * (R + 1);  
    private readonly uint[] Q; 

    public ReEncrypt(string inputKey)
    {
        if (inputKey == null) inputKey = "";
        byte[] keyBytes = Encoding.UTF8.GetBytes(inputKey);
        byte[] key = new byte[l];
        int copyLen = Math.Min(keyBytes.Length, l);
        Array.Copy(keyBytes, key, copyLen);
        Q = KeySchedule(key);
    }
    public string Execute(string base64Cipher)
    {
        if (base64Cipher == null) base64Cipher = "";
        byte[] cipher;
        cipher = Convert.FromBase64String(base64Cipher);
        int blockSize = 8;
        byte[] plainData = new byte[cipher.Length];
        for (int i = 0; i < cipher.Length; i += blockSize)
        {
            byte[] block = new byte[blockSize];
            Array.Copy(cipher, i, block, 0, blockSize);
            byte[] dec = DecryptBlock(block);
            Array.Copy(dec, 0, plainData, i, blockSize);
        }
        int realLen = plainData.Length;
        while (realLen > 0 && plainData[realLen - 1] == 0) realLen--;
        return Encoding.UTF8.GetString(plainData, 0, realLen);
    }
    private uint[] KeySchedule(byte[] key)
    {
        int c = Math.Max(1, (key.Length + bytesPerWord - 1) / bytesPerWord);
        uint[] L = new uint[c];
        for (int i = key.Length - 1; i >= 0; i--)
        {
            L[i / bytesPerWord] = (L[i / bytesPerWord] << 8) + key[i];
        }
        uint[] Slocal = new uint[t];
        uint P = 0xb7e15163u;
        uint Qc = 0x9e3779b9u;
        Slocal[0] = P;
        for (int i = 1; i < t; i++)
        {
            Slocal[i] = Slocal[i - 1] + Qc;
        }
        int n = Math.Max(t, c);
        uint A = 0, B = 0;
        int ii = 0, jj = 0;
        for (int k = 0; k < 3 * n; k++)
        {
            A = Slocal[ii] = RotateLeft(Slocal[ii] + A + B, 3);
            B = L[jj] = RotateLeft(L[jj] + A + B, (int)((A + B) % 32));
            ii = (ii + 1) % t;
            jj = (jj + 1) % c;
        }
        return Slocal;
    }
    private byte[] DecryptBlock(byte[] block)
    {
        uint A = BitConverter.ToUInt32(block, 0);
        uint B = BitConverter.ToUInt32(block, 4);
        for (int i = R; i >= 1; i--)
        {
            B = RotateRight(B - Q[2 * i + 1], (int)(A % 32)) ^ A;
            A = RotateRight(A - Q[2 * i], (int)(B % 32)) ^ B;
        }
        B = B - Q[1];
        A = A - Q[0];
        byte[] outBlock = new byte[8];
        Array.Copy(BitConverter.GetBytes(A), 0, outBlock, 0, 4);
        Array.Copy(BitConverter.GetBytes(B), 0, outBlock, 4, 4);
        return outBlock;
    }
    private static uint RotateLeft(uint x, int y)
    {
        int s = y & 31;
        return (x << s) | (x >> (32 - s));
    }
    private static uint RotateRight(uint x, int y)
    {
        int s = y & 31;
        return (x >> s) | (x << (32 - s));
    }
}

