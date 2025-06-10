import cpp

class OverflowCandidate extends FunctionCall {
  OverflowCandidate() {
    this.getTarget().getName() = "strcpy" or
    this.getTarget().getName() = "gets"
  }

  override string toString() { result = "Potential buffer overflow via " + this.getTarget().getName() }
}

from OverflowCandidate call
select call, "Potential buffer overflow detected due to unsafe function call."
