package com.instagram.identity.controller.buyer;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * This controller contains endpoints accessible ONLY to BUYER users.
 *
 * SecurityConfig restricts:
 *    .requestMatchers("/buyer/**").hasRole("BUYER")
 */
@RestController
@RequestMapping("/buyer")
public class BuyerController {

    /**
     * A sample protected endpoint only for buyers.
     */
    @GetMapping("/orders")
    public String buyerOrders() {
        return "Buyer Orders (Buyer role required)";
    }
}
