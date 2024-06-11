// utility to be used in the place of redis or some other cache
class TimedArray {
    constructor(holdTime) {
      this.array = [];
      this.holdTime = holdTime; // hold time in milliseconds
    }
  
    addElement(element) {
      this.array.push(element);
      console.log(`Added: ${element}, Array: ${this.array}`);
  
      setTimeout(() => {
        this.removeElement(element);
      }, this.holdTime);
    }
  
    removeElement(element) {
      const index = this.array.indexOf(element);
      if (index > -1) {
        this.array.splice(index, 1);
        console.log(`Removed: ${element}, Array: ${this.array}`);
      }
    }
    getCurrentArray() {
        return this.array;
      }
  }
  
  export default TimedArray;
  