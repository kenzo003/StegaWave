import java.io.IOException;
import java.util.Scanner;

public class Test {
    public static void main(String[] args) throws IOException {
        int option = 0;
        Scanner scanner = new Scanner(System.in);
        // Steganography steg = new Steganography();
        // steg.encrypt("hp+.wav", "hp.wav", "message.txt", 16);
        // steg.decrypt("hp.wav", "message2.txt", 16);
        System.out.println("Стеганография WAV");
        System.out.println("\t1. Encode");
        System.out.println("\t2. Decode");
        System.out.println("\t0. Exit");

        while (true) {
            System.out.print("\nYour option: ");
            option = scanner.nextInt();

            switch (option) {
                case 1:
                    Scanner scanner_enc = new Scanner(System.in);
                    String[] opt_enc = new String[4];
                    System.out.print("Name of WAV input audio file: ");
                    opt_enc[0] = scanner_enc.nextLine();
                    System.out.print("Name of WAV output audio file: ");
                    opt_enc[1] = scanner_enc.nextLine();
                    System.out.print("Name of input text file: ");
                    opt_enc[2] = scanner_enc.nextLine();
                    System.out.print("Degree: ");
                    opt_enc[3] = scanner_enc.nextLine();

                    if (Steganography.encrypt(opt_enc[0], opt_enc[1], opt_enc[2], Integer.parseInt(opt_enc[3]))) {
                        System.out.println("\tMessage successfully encoded");
                    } else
                        System.out.println("\tError encoding message");
                    break;
                case 2:
                    Scanner scanner_dec = new Scanner(System.in);
                    String[] opt_dec = new String[3];
                    System.out.print("Name of WAV input audio file: ");
                    opt_dec[0] = scanner_dec.nextLine();
                    System.out.print("Name of output text file: ");
                    opt_dec[1] = scanner_dec.nextLine();
                    System.out.print("Degree: ");
                    opt_dec[2] = scanner_dec.nextLine();

                    if (Steganography.decrypt(opt_dec[0], opt_dec[1], Integer.parseInt(opt_dec[2]))) {
                        System.out.println("\tMessage successfully decoded");
                    } else
                        System.out.println("\tError decoding message");
                    break;

                case 0:
                    return;

                default:
                    System.out.println("invalid option selected");
                    break;
            }
        }
    }
}
