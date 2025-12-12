package com.instagram.identity.controller.seller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Endpoints inside this controller can only be accessed by SELLER users.
 *
 * The access rule is:
 *    .requestMatchers("/seller/**").hasRole("SELLER")
 */
@RestController
@RequestMapping("/seller")
public class SellerController {

    /**
     * Example protected endpoint for sellers.
     */
    @GetMapping("/products")
    public String sellerProducts() {
        return "Seller Products (Seller role required)";
    }
}
