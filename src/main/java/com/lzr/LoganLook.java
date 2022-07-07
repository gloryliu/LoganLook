package com.lzr;

import org.apache.commons.cli.*;

import java.io.*;

/**
 * @author liuzhenrong
 * @date 2021/9/2 5:08 下午
 * @desc
 */
public class LoganLook {
    private static Options OPTIONS = new Options();
    private static CommandLine commandLine;
    private static String HELP_STRING = null;


    public static void main(String[] args) {
        initCliArgs(args);
    }

    private static void initCliArgs(String[] args) {
        CommandLineParser commandLineParser = new DefaultParser();
        OPTIONS.addOption(Option.builder("h").longOpt("help").type(String.class).desc("帮助").build());
        OPTIONS.addOption(Option.builder("i").required().hasArg(true).longOpt("input_file").type(String.class).desc("被加密文件").build());
        OPTIONS.addOption(Option.builder("o").longOpt("output_file").type(String.class).desc("输出文件").build());
        OPTIONS.addOption(Option.builder("k").required().hasArg(true).type(String.class).desc("key").build());
        OPTIONS.addOption(Option.builder("v").required().hasArg(true).type(String.class).desc("iv").build());

        try {
            commandLine = commandLineParser.parse(OPTIONS, args);
            if (!commandLine.hasOption("i") || !commandLine.hasOption("k") || !commandLine.hasOption("v")) {
                Log.i(getHelpString());
                return;
            }
            String input_file = commandLine.getOptionValue("i");
            String key = commandLine.getOptionValue("k");
            String iv = commandLine.getOptionValue("v");
            String output_file = "";
            if (commandLine.hasOption("o")) {
                output_file = commandLine.getOptionValue("o");
            } else {
                output_file = input_file + "_decode.txt";
            }
            decodeFile(input_file, output_file, key, iv);
        } catch (ParseException | IOException e) {
            Log.i(e.getMessage());
            Log.i(getHelpString());
        }
    }

    private static void decodeFile(String input_file, String output_file, String key, String iv) throws IOException {
        File inputFile = new File(input_file);
        if (!inputFile.exists()) {
            Log.i("文件不存在");
            return;
        }
        File outFile = new File(output_file);
        if (outFile == null) {
            Log.i("输出文件创建失败");
            return;
        }
        InputStream inputStream = new FileInputStream(inputFile);
        LoganProtocol loganProtocol = new LoganProtocol(inputStream, outFile, key, iv);
        if (loganProtocol.process()) {
            Log.i("解密成功");
        } else {
            Log.i("解密失败");
        }
    }

    private static String getHelpString() {
        if (HELP_STRING == null) {
            HelpFormatter helpFormatter = new HelpFormatter();
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            PrintWriter printWriter = new PrintWriter(byteArrayOutputStream);
            helpFormatter.printHelp(printWriter, HelpFormatter.DEFAULT_WIDTH, "-i input_path [-o output_path] -k key -v iv", null,
                    OPTIONS, HelpFormatter.DEFAULT_LEFT_PAD, HelpFormatter.DEFAULT_DESC_PAD, null);
            printWriter.flush();
            HELP_STRING = new String(byteArrayOutputStream.toByteArray());
            printWriter.close();
        }
        return HELP_STRING;
    }

}
