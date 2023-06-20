#include <cassert>
#include <cstdint>
#include <map>
#include <stack>
#include <vector>
#include <utility>

/* serialize parallel copy implementation, based on
 * https://github.com/pfalcon/parcopy
 * Allows fan out, does not allow fan in / dst smashing.
 */
std::vector<std::pair<uint64_t, uint64_t>>
serialize_parallel_copy(std::multimap<uint64_t, uint64_t> &moves,
                        uint64_t tmp_reg) {
  std::vector<std::pair<uint64_t, uint64_t>> res;

  for(auto&move : moves) {
    assert(move.first != tmp_reg);
    assert(move.second != tmp_reg);
  }

  std::stack<uint64_t> ready;
  std::map<uint64_t, uint64_t> rmoves;
  std::map<uint64_t, uint64_t> loc;
  for (auto &move : moves) {
    // Check for dest-smashing.
    assert(rmoves.find(move.second) == rmoves.end());
    rmoves[move.second] = move.first;
    loc[move.first] = move.first;
    if (moves.find(move.second) == moves.end()) {
      ready.push(move.second);
    }
  }
  while (!rmoves.empty()) {
    while (static_cast<unsigned int>(!ready.empty()) != 0U) {
      uint64_t r = ready.top();
      ready.pop();
      if (rmoves.find(r) == rmoves.end()) {
        continue;
      }
      auto rmove = loc[rmoves[r]];
      res.emplace_back(rmove, r);
      loc[rmove] = r;

      rmoves.erase(r);

      ready.push(rmove);
    }
    if (rmoves.empty()) {
      break;
    }

    auto b = rmoves.begin();
    auto from = b->second;
    auto to = b->first;
    rmoves.erase(b);
    if (from != to) {
      // There is a cycle, set one to tmp.
      res.emplace_back(from, tmp_reg);
      loc[tmp_reg] = tmp_reg; // Tmp is never a fan out target.
      ready.push(from);
      rmoves[to] = tmp_reg;
    }
  }

  // printf("Parallel copy in:\n");
  // for(auto&move : moves) {
  //   printf("%li to %li\n", move.first, move.second);
  // }
  // printf("Parallel copy out:\n");
  // for(auto&move : res) {
  //   printf("%li to %li\n", move.first, move.second);
  // }
  return res;
}

#if 0
uint64_t tmp = 101;
std::multimap<uint64_t, uint64_t> moves;
std::vector<std::pair<uint64_t, uint64_t>> expected;
void run_test() {
  auto res = serialize_parallel_copy(moves, tmp);
  if (res != expected) {
    printf("Got:\n");
    for(auto& r : res) {
      printf("Mov %li to %li\n", r.first, r.second);
    }
    printf("Expected:\n");
    for(auto& r : expected) {
      printf("Mov %li to %li\n", r.first, r.second);
    }
  }
  assert(res == expected);

  moves.clear();
  expected.clear();
}

int main() {

  // Trivial case
  tmp = 101;
  moves.insert(std::make_pair(1, 0));
  moves.insert(std::make_pair(2, 1));
  moves.insert(std::make_pair(3, 2));
  expected.push_back(std::make_pair(1, 0));
  expected.push_back(std::make_pair(2, 1));
  expected.push_back(std::make_pair(3, 2));
  run_test();

  // Self loop optimized away
  tmp = 1;
  moves.insert(std::make_pair(0, 0));
  run_test();

  // Loop with 2
  tmp = 2;
  moves.insert(std::make_pair(0, 1));
  moves.insert(std::make_pair(1, 0));
  expected.push_back(std::make_pair(1, tmp));
  expected.push_back(std::make_pair(0, 1));
  expected.push_back(std::make_pair(tmp, 0));
  run_test();

  // Loop with 3
  tmp = 0;
  moves.insert(std::make_pair(2, 1));
  moves.insert(std::make_pair(3, 2));
  moves.insert(std::make_pair(1, 3));
  expected.push_back(std::make_pair(2, tmp));
  expected.push_back(std::make_pair(3, 2));
  expected.push_back(std::make_pair(1, 3));
  expected.push_back(std::make_pair(tmp, 1));
  run_test();
  

  // Two loops of 2
  tmp = 4;
  moves.insert(std::make_pair(1, 0));
  moves.insert(std::make_pair(0, 1));
  moves.insert(std::make_pair(2, 3));
  moves.insert(std::make_pair(3, 2));
  expected.push_back(std::make_pair(1, tmp));
  expected.push_back(std::make_pair(0, 1));
  expected.push_back(std::make_pair(tmp, 0));
  expected.push_back(std::make_pair(3, tmp));
  expected.push_back(std::make_pair(2, 3));
  expected.push_back(std::make_pair(tmp, 2));
  run_test();

  // Simple fan out
  tmp = 4;
  moves.insert(std::make_pair(1, 2));
  moves.insert(std::make_pair(1, 3));
  expected.push_back(std::make_pair(1, 3));
  expected.push_back(std::make_pair(3, 2));
  run_test();

  // More complex fan out
  tmp = 5;
  moves.insert(std::make_pair(4, 1)); 
  moves.insert(std::make_pair(1, 2)); 
  moves.insert(std::make_pair(1, 3));
  moves.insert(std::make_pair(3, 4)); 
  expected.push_back(std::make_pair(1, 2));
  expected.push_back(std::make_pair(4, 1));
  expected.push_back(std::make_pair(3, 4));
  expected.push_back(std::make_pair(2, 3));
  run_test();

  // More complex fan out
  tmp = 0;
  moves.insert(std::make_pair(1,2));
  moves.insert(std::make_pair(2,3));
  moves.insert(std::make_pair(3,1));
  moves.insert(std::make_pair(3,4));
  expected.push_back(std::make_pair(3, 4));
  expected.push_back(std::make_pair(2, 3));
  expected.push_back(std::make_pair(1, 2));
  expected.push_back(std::make_pair(4, 1));
  run_test();

  // Overlapping tmp
  tmp = 5;
  moves.insert(std::make_pair(3, 1));
  moves.insert(std::make_pair(1, 3));
  moves.insert(std::make_pair(2, 4));
  expected.push_back(std::make_pair(2, 4));
  expected.push_back(std::make_pair(3, tmp));
  expected.push_back(std::make_pair(1, 3));
  expected.push_back(std::make_pair(tmp, 1));
  run_test();

  return 0;
}

#endif
