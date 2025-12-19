package com.instagram.post.model;

import lombok.Data;

@Data
public class Location {
    private String name;
    private Double latitude;
    private Double longitude;
    private String placeId;
}