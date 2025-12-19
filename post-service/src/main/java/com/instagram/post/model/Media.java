package com.instagram.post.model;

import lombok.Data;

@Data
public class Media {
    private String mediaType;      // "image" or "video"
    private String url;
    private String thumbnailUrl;
    private String lowResUrl;
    private Integer width;
    private Integer height;
    private Long fileSize;
    private Integer duration;      // For videos
    private String altText;
    private Integer displayOrder;
}