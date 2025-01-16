package org.chhan.ex_jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Map;

public class Util {
    public static Map<String,Object> jsonToMap(String jsonData){
        ObjectMapper objectMapper = new ObjectMapper();
        try{
            Map<String, Object> convertMap = objectMapper.readValue(jsonData, Map.class);
            return convertMap;
        }catch (JsonProcessingException e){
            e.printStackTrace();
        }

        return null;
    }
}
