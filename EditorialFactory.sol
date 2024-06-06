// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC1155/extensions/ERC1155Supply.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract NftNowEditorial is ERC1155, EIP712, ERC1155Supply, AccessControl, Ownable {   
    using ECDSA for bytes32;
    using Strings for uint256;
    
    // Define struct for TokenInfo
    struct TokenInfo {
        bool exists;
        bool mintable;
        bool claimable;
        bool hasAllowlist;
        uint256 id;
        uint256 publicCost;
        uint256 maxAmount; 
        uint256 maxPerUser; 
        string metadataUrl;
        address author;
        address validator;
        uint256 allowlistCost;
    }

    // Define struct for publication description
    struct Article {
        string publisher;
        string category;
        string title;
        string author;
        // string description;
        uint256 id;
        uint timestamp;
    }

    struct Role{
        address account;
        uint id;
        uint timestamp;
    }
    
    Article[] private articles;
    Role[] public roles;

    //*****Variables 
    string public name;
    string public publisher;
    string private  SIGNING_DOMAIN;
    string private constant SIGNATURE_VERSION = "1";
    bool paused = true;
    address public initialOwner = msg.sender;

    bytes32 public constant AUTHOR_ROLE = keccak256("AUTHOR");


    //*****MAPPINGS    
    // Mapping from token id to token info
    mapping(uint256 => TokenInfo) public tokenInfos; 

    // Mapping from token id to article info
    mapping(uint256 => Article) public articleInfo; 
        
    //Mapping who has claimed 1 free per tokenId
    mapping(uint => mapping(address => bool)) public alreadyClaimed; 

    //Mapping of authors
    mapping(address => bool) public authors;

    //Mapping for max mint per user
    mapping(uint => mapping(address => uint)) public addressMintedBalance;

    //*****EVENTS 
    // Define event for when a new article is created
    event ArticleCreated(uint articleId, string title, string author, uint timestamp);
    // Define event for when a new article is minted
    event ArticleMinted(uint articleId, uint timestamp);
    // Define event for when a article is updated
    event ArticleUpdated(uint articleId, uint timestamp, string metadataUrl);
    //Define event for airdropping tokens
    event ArticleAirdropped(uint articleId, uint timestamp);

     //*****ERROR REVERTS
    error Paused();
    error nonExistentId();
    error nonMintable();
    error allowlistOnly();
    error lowSupply();
    error maxPerWallet();
    error exceedsBalance();
    error notEnoughEth();
    error cantMint();


    constructor(string memory _name, string memory _publisher, string memory _signingDomain, address _owner) Ownable() ERC1155("NftNowEditorial") EIP712(SIGNING_DOMAIN, SIGNATURE_VERSION) payable {
        name = _name;
        publisher = _publisher;
        SIGNING_DOMAIN = _signingDomain;
        
        _grantRole(DEFAULT_ADMIN_ROLE, _owner);
        _setRoleAdmin(AUTHOR_ROLE, DEFAULT_ADMIN_ROLE);
        initialOwner = _owner;
        
    }
    
    modifier onlyAdmin() {
        require(isAdmin(msg.sender), "Restricted to admins.");
        _;
    }

    modifier onlyAuthor() {
        require(isAuthor(msg.sender), "Restricted to authors.");
        _;
    }

    modifier canEdit(uint256 _id) {
        require(isAdmin(msg.sender) || tokenInfos[_id].author == msg.sender, "Only authors can edit their own posts.");
        _;
    }  

    //*******************************************************************************************
    //*******************************************************************************************
    //*****Creator function
    
    // Function to create a new article
    function createArticle(string memory _category, string memory _title, string memory _author, uint _publicCost, uint _maxAmount, uint _maxPerUser, string memory _metadataUrl, address _validator, uint _reserveAmount, address _reserveAddy, uint256 _allowlistCost) public onlyAuthor {
        
        // Add new article to article array
        articles.push(Article(publisher, _category, _title, _author, articles.length, block.timestamp));
                
        //Add tokenId to array for 1155s
        add(articles.length, _publicCost, _maxAmount, _maxPerUser, _metadataUrl, msg.sender, _validator, _allowlistCost);
        
        authors[msg.sender] = true;
        //Optionally mint some to specified wallet
        if (_reserveAmount > 0) {
            _mint(_reserveAddy, articles.length, _reserveAmount, "");            
        }
        
        // Emit ArticleCreated event
        emit ArticleCreated(articles.length, _title, _author, block.timestamp);
    }

    function _beforeTokenTransfer(
            address operator,
            address from,
            address to,
            uint256[] memory ids,
            uint256[] memory amounts,
            bytes memory data
        ) internal override(ERC1155, ERC1155Supply) {
            super._beforeTokenTransfer(operator, from, to, ids, amounts, data);
            // Add your custom implementation here
        }

    //*****Distribution functions
 
    function mintCheck(TokenInfo memory tokenInfo, uint256 tokenId, uint256 minted, uint256 amount) internal view returns(bool){
        if (paused == true) revert Paused();

        // Ensure token id exists 
        if(tokenInfo.exists == false) revert nonExistentId();

        // Ensure tokenId is mintable
        if(tokenInfo.mintable == false) revert nonMintable();

        // Prevent minting more than allowed by the contract
        if((minted + amount) > tokenInfo.maxAmount) revert lowSupply();

        //Max amount to mint per wallet
        if((balanceOf(msg.sender, tokenId) + amount) > tokenInfo.maxPerUser) revert maxPerWallet();

        //Number of already minted by user
        if(addressMintedBalance[tokenId][msg.sender] + amount > tokenInfo.maxPerUser) revert exceedsBalance();   
         
        return true;
    }

    function mint(uint256 tokenId, uint256 amount) public payable {
        
        // Get token information for token id
        TokenInfo memory tokenInfo = tokenInfos[tokenId];
    
        // Get amount of already minted tokens for this tokenId
        uint256 minted = super.totalSupply(tokenId);

        //Check the mint conditions
        if (mintCheck(tokenInfo, tokenId, minted, amount) == false) revert cantMint();

        //Require eth sent
        if(tokenInfos[tokenId].publicCost * amount < msg.value) revert notEnoughEth();    

        // Ensure tokenId allowlist time elapsed
        if(tokenInfo.hasAllowlist == true) revert allowlistOnly();         
        
        //increment minted balance per user
        addressMintedBalance[tokenId][msg.sender] += amount;
        
        // Mint token
        _mint(msg.sender, tokenId, amount, "");
        
        // Emit ArticleMinted event
        emit ArticleMinted(tokenId, block.timestamp);
         
    }


    //Allowlist Mint
    function allowlistMint(uint256 tokenId, uint256 amount, uint nonce, address addr, bytes calldata signature) public payable {
        
        // Get token information for token id
        TokenInfo memory tokenInfo = tokenInfos[tokenId];

        // Get amount of already minted tokens for this tokenId
        uint256 minted = super.totalSupply(tokenId);

        //ECDSA
        require(check(tokenId, nonce, addr, signature) == tokenInfo.validator, "Not verified");
        
        //Check the mint conditions
        if (mintCheck(tokenInfo, tokenId, minted, amount) == false) revert cantMint();

        // Ensure tokenId allowlist time elapsed
        if(tokenInfo.hasAllowlist == false) revert allowlistOnly(); 
        
        //Require eth sent
        if(tokenInfos[tokenId].allowlistCost * amount < msg.value) revert notEnoughEth();

        //increment minted balance per user
        addressMintedBalance[tokenId][msg.sender] += amount;

        //switch claim counter per user
        alreadyClaimed[tokenId][msg.sender] = true;
        
        // Mint token
        _mint(msg.sender,tokenId, amount, "");
        
        emit ArticleMinted(tokenId, block.timestamp);
    }

    //@dev used for ECDSA signature verification

    function check(uint256 tokenId, uint256 nonce, address addr, bytes memory signature) public view returns (address) 
        {
            return _verify(tokenId, nonce, addr, signature);
        }

        function _verify(uint256 tokenId, uint256 nonce, address addr, bytes memory signature) internal view returns (address) 
        {
            bytes32 digest = _hash(tokenId, nonce, addr);
            return ECDSA.recover(digest, signature);
        }

        function _hash(uint256 tokenId, uint256 nonce, address addr) internal view returns (bytes32) 
        {
            return _hashTypedDataV4(keccak256(abi.encode(
                keccak256("Web3Struct(uint256 tokenId,uint256 nonce,address addr)"),
                tokenId,
                nonce,
                addr
        )));
    }


    
    //Allows user to claim 1 free tokenId based on ECDSA signature
    
    // function claim(uint256 tokenId, uint nonce, address addr, bytes calldata signature) public payable {
        
    //     // Get token information for token id
    //     TokenInfo memory tokenInfo = tokenInfos[tokenId];

    //     // Get amount of already minted tokens for this tokenId
    //     uint256 minted = super.totalSupply(tokenId); 

    //     //ECDSA
    //     require(check(tokenId, nonce, addr, signature) == tokenInfo.validator, "Not verified");
       
    //     //Require contract is not paused
    //     if (paused == true) revert Paused();

    //     // Ensure token id exists 
    //     if(tokenInfo.exists == false) revert nonExistentId();

    //     //Require token is claimable
    //     if(tokenInfo.claimable == false) revert cantClaim();
        
    //     // Prevent minting more than allowed
    //     if((minted + 1) > tokenInfo.maxAmount) revert lowSupply();

    //     //Require 1 per user signature
    //     if(alreadyClaimed[tokenId][msg.sender] == true) revert exceedsBalance();

    //     //switch claim balance per user
    //     alreadyClaimed[tokenId][msg.sender] = true;
        
    //     _mint(msg.sender,tokenId, 1, "");
         
        
    //     emit ArticleMinted(tokenId, block.timestamp);
    // }
 
    //Allows owner to airdrop token to multiple users
    //WARNING for onlyOwner: No checks performed. Use with caution.
    
    function bulkDrop(address[] calldata users, uint tokenId) external onlyAdmin{
        // Get token information for token id
        TokenInfo memory tokenInfo = tokenInfos[tokenId];
    
        // Get amount of already minted tokens for this tokenId
        uint256 minted = super.totalSupply(tokenId);

        //Require contract is not paused
        if (paused == true) revert Paused();

        // Ensure token id exists 
        if(tokenInfo.exists == false) revert nonExistentId();

        if((minted + users.length) > tokenInfo.maxAmount) revert lowSupply();
        
        for (uint256 i; i < users.length; ++i) {
            _mint(users[i], tokenId, 1, ""); 
            
            //increment minted balance per user
            addressMintedBalance[tokenId][users[i]] += 1;
        }
        
        emit ArticleAirdropped(tokenId, block.timestamp);
    }

    //*****Data functions

    // Token level metadata 
    function uri(uint256 tokenId) public view override returns (string memory) {
        return tokenInfos[tokenId].metadataUrl;
    }
    
    // Function to get all articles
    function getAllarticles() public view returns (Article[] memory) {
        return articles;
    }
    
    // Function to get a article by ID
    function getArticleById(uint _articleId) public view returns (Article memory) {
        Article memory a = articles[_articleId];
        return a;
    }
    
    //*****Internal functions

    function add(uint256 tokenId, uint256 publicCost, uint256 maxAmountAllowed, uint256 maxPerUser, string memory metadataUrl, address author, address validator, uint256 allowlistCost) internal {
        // Ensure we can only add and not override
        require(!tokenInfos[tokenId].exists, "Token with given id already exists"); 
        
        // Add token informations for token id
        tokenInfos[tokenId] = TokenInfo(true, false, false, false, articles.length, publicCost, maxAmountAllowed, maxPerUser, metadataUrl, author, validator, allowlistCost); 
    }

    //*****OnlyOwner functions

    function isAdmin(address account) public virtual view returns (bool) {
        return hasRole(DEFAULT_ADMIN_ROLE, account);
    }

    /// @dev Return `true` if the account belongs to the user role.
    function isAuthor(address account) public virtual view returns (bool) {
        return hasRole(AUTHOR_ROLE, account);
    }

    /// @dev Add an account to the user role. Restricted to admins.
    function addAuthor(address account) public virtual onlyOwner {
        grantRole(AUTHOR_ROLE, account);
        roles.push(Role(account, roles.length, block.timestamp));
    }

    /// @dev Add an account to the admin role. Restricted to admins.
    function addAdmin(address account) public virtual onlyOwner {
        grantRole(DEFAULT_ADMIN_ROLE, account);
    }

    /// @dev Remove an account from the user role. Restricted to admins.
    function removeAuthor(address account) public virtual onlyOwner {
        revokeRole(AUTHOR_ROLE, account);
    }

    /// @dev Remove oneself from the admin role.
    function renounceAdmin() public virtual {
        renounceRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }
    
    //withdraws all remaining funds from the smart contract
    //send ZERO value to when calling
    function withdraw() public payable onlyAdmin {
        (bool success, ) = payable(msg.sender).call{value: address(this).balance}("");
        require(success);
    }

    //Pause the entire contract
    function pause(bool _state) public onlyAdmin(){
        paused = _state;
    }

    // Update token metadataURI for token id to allow edits
    function editURI(uint tokenId, string memory _metadataUrl) public canEdit(tokenId){
        require(tokenInfos[tokenId].exists, "Token with given id does not exist"); 
        tokenInfos[tokenId].metadataUrl = _metadataUrl;

        emit ArticleUpdated(tokenId, block.timestamp, _metadataUrl);
    }

    //Set mintable state for tokenId
    function setMintable(uint tokenId, bool _state) public onlyAdmin{
        tokenInfos[tokenId].mintable = _state;
    }

    //Set claimable state for tokenId
    // function setClaimable(uint tokenId, bool _state) public onlyAdmin{
    //     tokenInfos[tokenId].claimable = _state;
    // }

    //Set allowlist state for tokenId
    function setAllowlist(uint tokenId, bool _state) public onlyAdmin{
        tokenInfos[tokenId].hasAllowlist = _state;
    }

    //Set cost for allowlist mints on tokenId
    function setAllowlistCost(uint tokenId, uint256 _cost) public onlyAdmin{
        tokenInfos[tokenId].allowlistCost = _cost;
    }

    //Set paused state for contract
    function isPaused() public view returns(bool){
        return paused;
    }
    
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC1155, AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
    

}

contract EditorialFactory is Ownable {
    // Define struct for editorial description
    struct Editorial {
        string name;
        string publisher;
        address owner;
        address contractAddy;
        uint256 id;
        uint timestamp;
    }

    address public initialOwner = msg.sender;

    NftNowEditorial[] public editorials;
    Editorial[] public editorialRecord;

    constructor() Ownable() payable { }
    
    function create(string memory _name, string memory _publisher, string memory _signingDomain, address _owner) public payable onlyOwner {
        
        NftNowEditorial editorial = new NftNowEditorial(_name, _publisher, _signingDomain, _owner);
        
         // Add new article to article array
        editorialRecord.push(Editorial( _name, _publisher, _owner, address(editorial), editorialRecord.length, block.timestamp));
        
        //editorial.transferOwnership(_owner);
        editorials.push(editorial);

        editorial.transferOwnership(_owner);        
    }    
}