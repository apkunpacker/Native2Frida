import java.io.IOException;
import java.lang.String;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.HashMap;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.FileInputStream;
/*
Coded By Rahat
*/
public class Native2Frida {
    //make it true if you want to accept duplicate address
    private static boolean acceptDuplicates = false;
    private static String methodNameRegex = "(\\bchar\\b[^;{}=()]*?|)sub_(.*?)\\(([\\w\\W]*?)\\)";
    private static String charParameterRegex = "\\bchar\\b";

    public static boolean isEmpty(String str) {
        return str == null || str.trim().length() == 0;
    }
    
    public static String readFile(String str) throws IOException {
        StringBuilder chunks = new StringBuilder();
        BufferedReader buff = new BufferedReader(new InputStreamReader(new FileInputStream(str)));
        String line;
        while ((line = buff.readLine()) != null) {
            chunks.append(line);
            chunks.append("\n");
        }
        return chunks.toString().trim();
    }

    public static void main(String[] args) {
        HashMap<String, Integer> hookedMethods = new HashMap<String, Integer>();
        StringBuilder str = new StringBuilder();
        
        try {
            String content = readFile("/storage/emulated/0/Test/Test.c");           
            int addrCount = 0;
            Pattern pat = Pattern.compile(methodNameRegex);
            Pattern paramMatcher = Pattern.compile(charParameterRegex);
            Matcher mat = pat.matcher(content);
            while (mat.find()) {
                if (!acceptDuplicates && hookedMethods.containsKey("0x".concat(mat.group(2))))
                    continue;
                if (!isEmpty(mat.group(1)))
                    if (mat.group(1).startsWith("char")) {
                        if (!acceptDuplicates)
                            hookedMethods.put("0x".concat(mat.group(2)), addrCount);
                        str.append("var addr");
                        str.append(addrCount);
                        str.append(" = libbase.add(0x");
                        str.append(mat.group(2));
                        str.append(");\n");
                        str.append("Interceptor.attach(addr");
                        str.append(addrCount);
                        str.append(", {\n");
                        str.append("\tonEnter: function(args) {},\n");
                        str.append("\tonLeave: function(retval) {\n");
                        str.append("\t\tconsole.warn(\"Return 0x");
                        str.append(mat.group(2));
                        str.append(": \", retval.readCString());\n\t}\n})\n");
                        addrCount++;
                        continue;
                    }
                if (!isEmpty(mat.group(3))) {
                    if (paramMatcher.matcher(mat.group(3)).find()) {
                        int indexOfChar = 0;
                        if (!acceptDuplicates)
                            hookedMethods.put("0x".concat(mat.group(2)), addrCount);
                        str.append("var addr");
						str.append(addrCount);
						str.append(" = libbase.add(0x");
						str.append(mat.group(2));
						str.append(");\n");
                        str.append("Interceptor.attach(addr");
						str.append(addrCount);
						str.append(", {\n");
                        str.append("\tonEnter: function(args) {\n");
                        str.append("\t\tconsole.log(\"0x");
					    str.append(mat.group(2));
						str.append(" : \",");
                        String[] params = mat.group(3).split(",");
                        for (int i = 0; i < params.length; i++) {
                            if (paramMatcher.matcher(params[i]).find()) {
                                indexOfChar = i;
                                str.append(" args[");
								str.append(indexOfChar);
						        str.append("].readCString(),");
                            }
                        }
                        str.append(");\n\t},\n");
                        str.append("\tonLeave: function(retval) {\n");
                        str.append("\t\tconsole.warn(\"Return 0x");
						str.append(mat.group(2));
						str.append(": \", retval);\n\t}\n})\n");
                        addrCount++;
                    }
                    }
            }
            System.out.println(str.toString().replace(",)", ")"));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
