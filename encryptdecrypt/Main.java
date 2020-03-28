package encryptdecrypt;

import java.io.*;
import java.util.Arrays;
import java.util.Scanner;

public class Main {

    private static String saveFile = "";

    public static void main(String[] args) {
        String mode = "enc";
        String data = "";
        int key = 0;
        String algorithm = "";

        if (args.length > 0 && args.length % 2 == 0) {
            for (int i = 0; i < args.length - 1; i += 2) {
                String arg = args[i];

                if ("-mode".equals(arg)) {
                    mode = args[i + 1];
                } else if ("-key".equals(arg)) {
                    key = Integer.parseInt(args[i + 1]);
                } else if ("-data".equals(arg)) {
                    data = args[i + 1];
                } else if ("-out".equals(arg)) {
                    saveFile = args[i + 1];
                } else if ("-in".equals(arg) && data.isEmpty()) {
                    data = readDataFromFile(args[i + 1]);
                } else if ("-alg".equals(arg)) {
                    algorithm = args[i + 1];
                }
            }
        } else {
            System.out.println("Error. Wrong commands.");
        }

        switch (mode) {
            case "enc":
                encryptMessage(data, key, algorithm);
                break;
            case "dec":
                decryptMessage(data, key, algorithm);
                break;
            default:
                System.out.println("Wrong command.");
        }
    }

    private static String readDataFromFile(String path) {
        File file = new File(path);
        String data = "";

        try (Scanner scanner = new Scanner(file)) {
            data = scanner.nextLine();
        } catch (FileNotFoundException e) {
            System.out.println("Error. File not found.");
        }

        return data;
    }

    private static void decryptMessage(String str, int key, String algorithm) {

        MessageDecryptor messageDecryptor = new MessageDecryptor();
        switch (algorithm) {
            case "unicode":
                messageDecryptor.setDecryptingMethod(new DecryptUnicodeMessage());
                break;
            case "shift":
                messageDecryptor.setDecryptingMethod(new DecryptShiftMessage());
                break;
            default:
                messageDecryptor.setDecryptingMethod(new DecryptShiftMessage());
        }

        String  decrypt = messageDecryptor.decrypt(str, key);

        if ("".equals(saveFile)) {
            System.out.println(decrypt);
        } else {
            saveResult(decrypt);
        }

    }

    private static void encryptMessage(String str, int key, String algorithm) {

        MessageEncrypter messageEncrypter = new MessageEncrypter();
        switch (algorithm) {
            case "unicode":
                messageEncrypter.setEncryptingMethod(new EncryptUnicodeMessage());
                break;
            case "shift":
                messageEncrypter.setEncryptingMethod(new EncryptShiftMessage());
                break;
            default:
                messageEncrypter.setEncryptingMethod(new EncryptShiftMessage());
        }

        String encrypt = messageEncrypter.encrypt(str, key);

        if ("".equals(saveFile)) {
            System.out.println(encrypt);
        } else {
            saveResult(encrypt);
        }
    }

    private static void saveResult(String data) {
        File file = new File(saveFile);
        try (PrintWriter fw = new PrintWriter(file)) {
            fw.println(data);
        } catch (FileNotFoundException e) {
            System.out.println("Error. File not found.");
        }
    }
}

interface EncryptingMethod {
    String encrypt(String message, int key);
}

interface DecryptingMethod {
    String decrypt(String message, int key);
}

class MessageDecryptor {

    private DecryptingMethod decryptingMethod;

    public void setDecryptingMethod(DecryptingMethod decryptingMethod) {
        this.decryptingMethod = decryptingMethod;
    }

    public String decrypt(String message, int key) {
        return decryptingMethod.decrypt(message, key);
    }
}

class DecryptShiftMessage implements DecryptingMethod {

    @Override
    public String decrypt(String message, int key) {
        char[] splitMessage = message.toCharArray();
        var lowAlphabet = Arrays.asList("abcdefghijklmnopqrstuvwxyz".split(""));
        var upperAlphabet = Arrays.asList("ABCDEFGHIJKLMNOPQRSTUVWXYZ".split(""));
        StringBuilder encrypt = new StringBuilder();

        for (char c : splitMessage) {
            char newChar = c;
            if (lowAlphabet.contains(Character.toString(newChar))
                    || upperAlphabet.contains(Character.toString(newChar))) {
                int count = 0;
                while (count < key) {
                    if (newChar == 'a') {
                        newChar = 'z';
                        count++;
                        continue;
                    } else if (newChar == 'A') {
                        newChar = 'Z';
                        count++;
                        continue;
                    }
                    count++;
                    newChar--;
                }
            }
            encrypt.append(newChar);
        }

        return encrypt.toString();
    }
}

class DecryptUnicodeMessage implements DecryptingMethod {

    @Override
    public String decrypt(String message, int key) {
        char[] splitMessage = message.toCharArray();
        StringBuilder decrypt = new StringBuilder();

        for (int i = 0; i < splitMessage.length; i++) {
            char newChar = (char) (splitMessage[i] - key);
            decrypt.append(newChar);
        }

        return decrypt.toString();
    }
}

class EncryptShiftMessage implements EncryptingMethod {

    @Override
    public String encrypt(String message, int key) {

        char[] splitMessage = message.toCharArray();
        var lowAlphabet = Arrays.asList("abcdefghijklmnopqrstuvwxyz".split(""));
        var upperAlphabet = Arrays.asList("ABCDEFGHIJKLMNOPQRSTUVWXYZ".split(""));
        StringBuilder encrypt = new StringBuilder();

        for (char c : splitMessage) {
            char newChar = c;
            if (lowAlphabet.contains(Character.toString(newChar))
                    || upperAlphabet.contains(Character.toString(newChar))) {
                int count = 0;
                while (count < key) {
                    if (newChar == 'z') {
                        newChar = 'a';
                        count++;
                        continue;
                    } else if (newChar == 'Z') {
                        newChar = 'A';
                        count++;
                        continue;
                    }
                    count++;
                    newChar++;
                }
            }
            encrypt.append(newChar);
        }

        return encrypt.toString();
    }
}

class EncryptUnicodeMessage implements EncryptingMethod {

    @Override
    public String encrypt(String message, int key) {
        char[] splitMessage = message.toCharArray();
        String encrypt = "";

        for (char c : splitMessage) {
            encrypt += (char) (c + key);
        }

        return encrypt;
    }
}

class MessageEncrypter {

    private EncryptingMethod encryptingMethod;

    public void setEncryptingMethod(EncryptingMethod encryptingMethod) {
        this.encryptingMethod = encryptingMethod;
    }

    public String encrypt(String message, int key) {
        return this.encryptingMethod.encrypt(message, key);
    }
}
