package io.github.avew.keycloak.provider;

public class PwnedPassword {
    private final String hashSuffix;
    private final int pwnCount;

    public PwnedPassword(String hashSuffix, int pwnCount) {
        this.hashSuffix = hashSuffix;
        this.pwnCount = pwnCount;
    }

    public String getHashSuffix() {
        return hashSuffix;
    }

    public int getPwnCount() {
        return pwnCount;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PwnedPassword that = (PwnedPassword) o;

        if (pwnCount != that.pwnCount) return false;
        return hashSuffix != null ? hashSuffix.equals(that.hashSuffix) : that.hashSuffix == null;
    }

    @Override
    public int hashCode() {
        int result = hashSuffix != null ? hashSuffix.hashCode() : 0;
        result = 31 * result + pwnCount;
        return result;
    }

    @Override
    public String toString() {
        return "PwnedPassword{" +
                "hashSuffix='" + hashSuffix + '\'' +
                ", pwnCount=" + pwnCount +
                '}';
    }
}