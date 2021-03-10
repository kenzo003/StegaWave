import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;


public class Steganography {
    static final int wBitsPerSample = 16;
    static final int WAV_HEADER_SIZE = 44;

    public static boolean encrypt(String inputWavName, String outputWavName, String messageFileName, int degree) throws IOException {
        if (degree != 2 && degree != 4 && degree != 8 && degree != 16 && degree != 1) {
            System.out.println("Degree value can be only 1/2/4/8/16");
            return false;
        }

        // Исходные Файлы
        FileInputStream inputWav = new FileInputStream(inputWavName); // Wav encoding
        FileInputStream messageFile = new FileInputStream(messageFileName); // Сообщение, которое прячем в WAV
        FileOutputStream outputWav = new FileOutputStream(outputWavName);

        byte wav_header[] = new byte[WAV_HEADER_SIZE]; //chunkRIFF
        inputWav.read(wav_header, 0, WAV_HEADER_SIZE); //Считываем инофрмацию до chunk DataSize включительно

        //Размер данных
        int data_size = ByteBuffer.wrap(wav_header, 40, 4).order(ByteOrder.LITTLE_ENDIAN).getInt() - 4; //Размер чанка Data
        int text_len = messageFile.available(); // Размер сообщения

        // Проверка на то помещается ли сообщение в чанк Data
        if (text_len > data_size * degree / wBitsPerSample) {
            System.out.println("Too big text to encode");
            inputWav.close();
            messageFile.close();
            return false;
        }

        //Записываем в результирующий файл заголовок RIFF
        outputWav.write(wav_header);


        //Записывем размер сообщения в WAV
        byte[] messageByte = ByteBuffer.wrap(BigInteger.valueOf(text_len).toByteArray()).order(ByteOrder.LITTLE_ENDIAN).array();
        byte[] messageSize = new byte[4];
        for (int i = 0, j = messageByte.length - 1; i < messageSize.length; i++, j--) {
            messageSize[i] = 0;
            if (j >= 0)
                messageSize[i] = messageByte[j];
        }
        outputWav.write(messageSize);


        byte[] data = new byte[data_size];
        inputWav.read(data, 0, data_size); //Считываем чанк Data

        //Создание маски
        int text_mask = createMaskText(degree);
        int sample_mask = createMaskSample(degree);

        // Запись сообщения в WAV
        while (true) {

            byte[] txt_symbol = new byte[1];
            messageFile.read(txt_symbol, 0, 1); // Считываем 1 символ сообщения

            // Если достигнут конец строки, то завершаем цикл
            if (txt_symbol[0] == 0)
                break;

            // Получаем код символа в ASCII
            int txt_ascii = (int) txt_symbol[0];
            txt_ascii <<= 8;

            int another_ascii = 0; //получаем код символа в ascii

            // Если отведенное количество бит = 16, то считываем еще 1 символ из сообщ-я и добавляем к уже имеющемуся
            if (degree == 16) {
                byte[] another_symbol = new byte[1];
                messageFile.read(another_symbol, 0, 1);
                if (another_symbol[0] == 0)
                    another_ascii = 0b0;
                else {
                    another_ascii = (int) another_symbol[0];
                }

                txt_ascii |= another_ascii;
            }


            //Помещаем символы в сэмпл
            for (int i = 0; i < 16; i += degree) {
                if (i == 0 && txt_symbol[0] == 0)
                    break;
                // Считываем данные сэмпла
                int sample = new BigInteger(Integer.toHexString(data[1]) + Integer.toHexString(data[0]), 16).intValue() & sample_mask;
                data = Arrays.copyOfRange(data, 2, data.length);// Удаляем из массива данных 2 первых байта

                int bits = txt_ascii & text_mask;
                bits >>= (16 - degree);

                sample |= bits;
                byte[] temp = BigInteger.valueOf(sample).toByteArray();

                byte[] sampl = {temp[1], temp[0]};
                outputWav.write(sampl);
                txt_ascii = (txt_ascii << degree) % 65536;
            }
        }

        //Записываем оставшиеся данные
        outputWav.write(data);
        outputWav.write(inputWav.read());

        inputWav.close();
        messageFile.close();
        outputWav.close();

        return true;
    }

    public static boolean decrypt(String inputWavName, String messageFileName, int degree) throws IOException {
        if (degree != 2 && degree != 4 && degree != 8 && degree != 16 && degree != 1) {
            System.out.println("Degree value can be only 1/2/4/8/16");
            return false;
        }

        // Исходные Файлы
        FileInputStream inputWav = new FileInputStream(inputWavName); // Wav encoding
        FileOutputStream messageFileDecoded = new FileOutputStream(messageFileName); // Сообщение, которое прячем в WAV

        byte wav_header[] = new byte[WAV_HEADER_SIZE]; //chunkRIFF
        byte text_size[] = new byte[4]; //MessageSize

        inputWav.read(wav_header, 0, WAV_HEADER_SIZE); //Считываем инофрмацию до chunk DataSize включительно
        inputWav.read(text_size, 0, 4); //Считываем информацию о размере зашифрованного сообщения

        //Размер данных
        int data_size = ByteBuffer.wrap(wav_header, 40, 4).order(ByteOrder.LITTLE_ENDIAN).getInt() - 4; //Размер чанка Data
        int text_len = ByteBuffer.wrap(text_size, 0, 4).order(ByteOrder.LITTLE_ENDIAN).getInt(); //Размер чанка MessageSize

//        // Проверка на то помещается ли сообщение в чанк Data
//        if (text_len > data_size * degree / wBitsPerSample) {
//            //System.out.println("Too long message to decrypt");
//            inputWav.close();
//            messageFileDecoded.close();
//            return false;
//        }

        byte[] data = new byte[text_len];
        inputWav.read(data, 0, text_len); //Считываем чанк Data

        //Создание маски
        int sample_mask = ~createMaskSample(degree);

        int read = 0;
        while (read < text_len) {
            int two_symbols = 0;
            for (int i = 0; i < 16; i += degree) {
                int sample = new BigInteger(Integer.toHexString(data[1]) + Integer.toHexString(data[0]), 16).intValue() & sample_mask;
                data = Arrays.copyOfRange(data, 2, data.length);// Удаляем из массива данных 2 первых байта

                two_symbols <<= degree;
                two_symbols |= sample;
            }
            int first_symbol = two_symbols >> 8;
            messageFileDecoded.write((char) first_symbol);
            read += 1;

            if ((char) first_symbol == '\n' && System.lineSeparator().length() == 2) {
                read += 1;
            }
            if (text_len - read > 0) {
                int second_symbols = two_symbols & 0b0000000011111111;
                messageFileDecoded.write((char) second_symbols);
                read += 1;
                if ((char) second_symbols == '\n' && System.lineSeparator().length() == 2) {
                    read += 1;
                }
            }
        }

        messageFileDecoded.close();
        inputWav.close();
        return true;
    }

    private static int createMaskText(int degree) {
        int text_mask = 0b1111111111111111;
        text_mask <<= (wBitsPerSample - degree);
        text_mask %= 65536; //Убираем все числа больше 8 байт
        return text_mask;
    }

    private static int createMaskSample(int degree) {
        int sample_mask = 0b1111111111111111;
        sample_mask >>= degree;
        sample_mask <<= degree;
        return sample_mask;
    }
}

