package com.instagram.post.dto;

public record LocationDTO(
        String name,
        Double latitude,
        Double longitude,
        String placeId
) {}