package com.instagram.identity.model;

/**
 * Instagram-style account types.
 *
 * NOT a security role - controls feature access and UI presentation.
 *
 * Design rationale:
 *  - PERSONAL: Default for all users (friends, family, regular posts)
 *  - CREATOR: Access to creator studio, analytics, monetization tools
 *  - BUSINESS: Business insights, ad tools, contact buttons, shopping
 *
 * Users can switch between types (except downgrading from Business requires review).
 * This is a USER PREFERENCE, not a security boundary.
 */
public enum AccountType {

    /**
     * Default account type for new registrations.
     * Can view, post, comment, message - basic Instagram features.
     */
    PERSONAL,

    /**
     * For influencers, artists, public figures.
     *
     * Additional features:
     *  - Creator Studio dashboard
     *  - Advanced analytics (reach, engagement, demographics)
     *  - Monetization tools (brand partnerships, badges)
     *  - Content insights
     *  - Professional tools
     */
    CREATOR,

    /**
     * For brands, companies, local businesses.
     *
     * Additional features:
     *  - Business profile (category, contact info)
     *  - Instagram Shopping
     *  - Ad creation tools
     *  - Business insights
     *  - Customer messaging tools
     *  - Promotions
     */
    BUSINESS
}
