module bytecode_dependency::foo {
    use amm::pool::{Self, Pool};

    public fun pool_values<A, B>(pool: &Pool<A, B>): (u64, u64, u64) {
        pool::pool_values(pool)
    }
}