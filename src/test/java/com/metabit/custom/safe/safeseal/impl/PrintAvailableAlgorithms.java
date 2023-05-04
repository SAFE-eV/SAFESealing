package com.metabit.custom.safe.safeseal.impl;

import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// derived and extended from  https://stackoverflow.com/a/44318752/448779

public class PrintAvailableAlgorithms
{
    private static final Pattern KEY_TYPE_PATTERN       = Pattern.compile("^(\\w+)[.].*$");
    private static final Pattern KEY_ALIAS_TYPE_PATTERN = Pattern.compile("^Alg[.]Alias[.](\\w+).*$");
    private static final Pattern KEY_OID_PATTERN        = Pattern.compile(".*?(\\d+(?:[.]\\d+){3,})$");

    public static void main(String[] args) throws Exception
        {
        Provider[] provs = Security.getProviders();
        for (Provider prov : provs)
            {
            System.out.printf("%n >>> Provider: %s <<< %n%n", prov.getName());

            SortedSet<String> typeAndOID = getTypeAndOIDStrings(prov);

            for (String entry : typeAndOID)
                {
                String[] typeAndOIDArray = entry.split("-");
                String type = typeAndOIDArray[0];
                String oid = typeAndOIDArray[1];
                Service service = prov.getService(type, oid);
                String algo = service.getAlgorithm();
                System.out.printf("Type: %s, OID: %s, algo: %s%n", type, oid, algo);
                }
            }

        }

    private static SortedSet<String> getTypeAndOIDStrings(Provider prov)
        {
        SortedSet<String> typeAndOID = new TreeSet<>();

        Set<Object> keys = prov.keySet();
        for (Object key : keys)
            {
            String keyString = key.toString();
            Matcher oidMatcher = KEY_OID_PATTERN.matcher(keyString);
            if (oidMatcher.matches())
                {
                // get OID from matched keyString
                String oid = oidMatcher.group(1);

                // determine type
                String type;
                Matcher aliasTypeMatcher = KEY_ALIAS_TYPE_PATTERN.matcher(keyString);
                if (aliasTypeMatcher.matches())
                    {
                    type = aliasTypeMatcher.group(1);
                    }
                else
                    {
                    Matcher typeMatcher = KEY_TYPE_PATTERN.matcher(keyString);
                    typeMatcher.matches();
                    type = typeMatcher.group(1);
                    }

                // algorithm parameters are not algorithms, so skip them
                if (type.equals("AlgorithmParameters"))
                    {
                    continue;
                    }

                // auto-removes dupes
                typeAndOID.add(type+"-"+oid);
                }
            }
        return typeAndOID;
        }
}
