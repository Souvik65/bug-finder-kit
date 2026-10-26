# Insecure Deserialization — Deep Dive Reference

## 1. What is a "Gadget Chain"?

A gadget is an existing piece of executable code in an application or its dependent libraries (e.g., Apache Commons Collections, Spring Framework, Jackson, Groovy) that was written for benign purposes, but whose invocation can be subverted when executed during deserialization.

A **gadget chain** links multiple gadgets together:
1. **Kick-off Gadget**: An entry method called automatically during deserialization (e.g., `readObject()`, `__wakeup()`, `__destruct()`, `equals()`, `hashCode()`).
2. **Intermediate Gadgets**: Classes whose methods perform actions like dynamic reflection (`Method.invoke()`), property transformation, or proxy invocation.
3. **Sink Gadget**: The final method call that achieves attacker objectives (e.g., `Runtime.getRuntime().exec()`, `ProcessBuilder.start()`, `FileOutputStream.write()`).

### The Ysoserial Ecosystem
- **Java:** `ysoserial` (Common chains: `CommonsCollections1-7`, `Spring1-2`, `Groovy1`, `Hibernate1`).
- **.NET:** `ysoserial.net` (Chains targeting `TypeConfuseDelegate`, `TextFormattingRunProperties`, `ActivitySurrogateSelector`).
- **PHP:** `PHPGGC` (PHP Generic Gadget Chains for Laravel, Symfony, Guzzle, Monolog, WordPress).

---

## 2. JEP 290 and Custom Serializer Filtering (Java)

Introduced in Java 9 (and backported to Java 8u121), JEP 290 allows applications to validate incoming classes, graph depth, array lengths, and stream size before object instantiation.

### Global Filter via System Property
```bash
# Add to JVM startup flags
-Djdk.serialFilter="maxbytes=1000000;maxdepth=10;maxarray=1000;com.mycompany.model.*;!*"
```

### Programmatic Filter Implementation (Java 9+)
```java
public class SecureObjectInputStream {
    public static Object safeDeserialize(byte[] data) throws Exception {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStream(bais)) {

            ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
                "com.mycompany.dto.UserProfile;" +
                "java.lang.String;" +
                "java.lang.Number;" +
                "!*" // Reject all other classes
            );
            ois.setObjectInputFilter(filter);
            return ois.readObject();
        }
    }
}
```

---

## 3. Jackson Polymorphic Deserialization Checklist

Jackson provides several settings that govern polymorphic deserialization:

### Dangerous Configurations
```java
// CRITICAL: Automatically accepts type information from JSON properties
mapper.enableDefaultTyping(); 
mapper.activateDefaultTyping(LaissezFaireSubTypeValidator.instance, ObjectMapper.DefaultTyping.NON_FINAL);
```

### Secure Configuration
```java
// SAFE: Explicit SubType Validator
BasicPolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
    .allowIfBaseType("com.mycompany.dto.")
    .allowIfSubType("com.mycompany.dto.")
    .build();

mapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL);
```

---

## 4. PHP Phar Deserialization Prevention

Phar archives store serialized metadata. When any filesystem function operates on a `phar://` URL, PHP unpackages and deserializes this metadata.

### Vulnerable Filesystem Functions:
- `file_exists()`, `is_file()`, `is_dir()`
- `file_get_contents()`, `file_put_contents()`
- `copy()`, `rename()`, `unlink()`
- `getimagesize()`, `exif_read_data()`
- `include`, `require`, `include_once`, `require_once`

### Prevention:
```php
function safe_file_check(string $userPath): bool {
    // 1. Block stream wrappers explicitly
    if (preg_match('/^[a-z0-9+.-]+:\/\//i', $userPath)) {
        throw new InvalidArgumentException("Stream wrappers are forbidden.");
    }

    // 2. Resolve to canonical sandboxed path
    $realPath = realpath($userPath);
    $baseDir = '/var/www/uploads/';
    
    if ($realPath === false || strpos($realPath, $baseDir) !== 0) {
        throw new InvalidArgumentException("Path traversal attempt.");
    }
    
    return file_exists($realPath);
}
```
